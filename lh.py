import time
import ccxt
from typing import List, Dict
from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify
from concurrent.futures import ThreadPoolExecutor
import logging
import sqlite3
from datetime import datetime, timedelta
import hashlib
import threading
import queue
import websocket
import json
import os
import pickle

# 配置日志和数据目录
DATA_DIR = 'data'
LOG_DIR = os.path.join(DATA_DIR, 'log')
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(filename=os.path.join(LOG_DIR, 'trading.log'), level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

executor = ThreadPoolExecutor(max_workers=10)  # 支持更多策略
trade_queue = queue.Queue()
trade_lock = threading.Lock()

latest_prices = {}
pairs_cache = {}
running_strategies = {}
websocket_instance = None
websocket_thread_running = False

TRADES_FILE = os.path.join(DATA_DIR, 'trades.pkl')
STRATEGIES_FILE = os.path.join(DATA_DIR, 'strategies.pkl')
API_CONFIGS_FILE = os.path.join(DATA_DIR, 'api_configs.pkl')
TRADES_DB = os.path.join(DATA_DIR, 'trades.db')

class Position:
    def __init__(self, entry_price: float, amount: float):
        self.entry_price = entry_price
        self.amount = amount

class TradingStrategy:
    def __init__(self, exchange_name: str, symbol: str, api_key: str, api_secret: str, password: str = None, **params):
        self.symbol = symbol.replace('/', '-') if exchange_name == 'okx' else symbol
        self.is_test_mode = params.get('is_test_mode', True)
        self.exchange_name = exchange_name
        self.api_key = api_key
        self.api_secret = api_secret
        self.password = password
        config = {
            'apiKey': api_key,
            'secret': api_secret,
            'enableRateLimit': True,
            'options': {'defaultType': 'spot'},
            'timeout': 30000,
            'headers': {'Content-Type': 'application/json', 'x-simulated-trading': '1' if self.is_test_mode else '0'}
        }
        if exchange_name == 'okx' and password:
            config['password'] = password
        self.exchange = getattr(ccxt, exchange_name)(config)
        self.running = False
        self.run_event = threading.Event()
        self.positions: List[Position] = params.get('positions', [])
        self.initial_price = params.get('initial_price', None)
        self.lowest_price = params.get('lowest_price', None)
        self.last_entry_price = params.get('last_entry_price', None)
        self.add_position_count = params.get('add_position_count', 0)
        self.params = params
        self.last_price = None
        self.last_message = ""
        self.last_update_time = None
        self.last_message_time = None

        self.initial_amount = params.get('initial_amount', 100.0)
        self.drop_percent = params.get('drop_percent', 10.0)
        self.rebound_percent = params.get('rebound_percent', 5.0)
        self.max_add_positions = params.get('max_add_positions', 2)
        self.add_drop_percent = params.get('add_drop_percent', 0.3)
        self.add_rebound_percent = params.get('add_rebound_percent', 0.01)
        self.add_multiplier = params.get('add_multiplier', 50.0)
        self.profit_target = params.get('profit_target', 10.0)
        self.profit_rebound = params.get('profit_rebound', 2.0)
        self.use_arbitrage = params.get('use_arbitrage', True)
        self.add_by_total = params.get('add_by_total', False)
        self.loop_execution = params.get('loop_execution', False)
        self.initial_open_price = params.get('initial_open_price', None)
        self.advanced_add = params.get('advanced_add', [])
        self.order_timeout = params.get('order_timeout', 0)

    def reset_state(self, current_price: float):
        self.initial_price = current_price
        self.lowest_price = current_price
        self.last_entry_price = None
        self.add_position_count = 0
        self.positions = []
        if not self.initial_open_price:
            self.initial_open_price = current_price
        self.last_message = "状态重置，新循环开始"
        self.last_message_time = time.time()
        self.last_update_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        logging.info(f"{self.symbol} 重置状态，新轮次开始，当前价格: {current_price}")

    def calculate_avg_cost(self) -> float:
        if not self.positions:
            return 0
        total_cost = sum(pos.entry_price * pos.amount for pos in self.positions)
        total_amount = sum(pos.amount for pos in self.positions)
        return total_cost / total_amount

    def get_current_price(self) -> float:
        price = latest_prices.get(self.symbol)
        if price is not None:
            logging.info(f"{self.symbol} 从 WebSocket 获取最新价格: {price}")
            self.last_update_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            return price
        logging.warning(f"{self.symbol} 未从 WebSocket 获取价格，回退到 REST API")
        try:
            ticker = self.exchange.fetch_ticker(self.symbol.replace('-', '/'))
            price = float(ticker['last'])
            self.last_update_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            logging.info(f"{self.symbol} 从 REST API 获取最新价格: {price}")
            return price
        except Exception as e:
            logging.error(f"{self.symbol} 获取实时价格失败: {e}")
            return 0

    def calculate_profit(self, current_price: float) -> float:
        total_cost = sum(pos.entry_price * pos.amount for pos in self.positions)
        total_value = sum(pos.amount * current_price for pos in self.positions)
        return total_value - total_cost

    def calculate_profit_percent(self, current_price: float) -> float:
        avg_cost = self.calculate_avg_cost()
        if avg_cost == 0:
            return 0
        return ((current_price - avg_cost) / avg_cost) * 100

    def calculate_closed_profit(self) -> float:
        with sqlite3.connect(TRADES_DB) as conn:
            c = conn.cursor()
            c.execute('SELECT SUM(profit) FROM trades WHERE symbol = ? AND action LIKE "%平仓"', (self.symbol,))
            result = c.fetchone()[0]
            return result if result else 0

    def get_purchase_details(self) -> tuple:
        total_amount = sum(pos.amount for pos in self.positions)
        total_cost = sum(pos.entry_price * pos.amount for pos in self.positions)
        return total_amount, total_cost

    def log_trade(self, action: str, price: float, amount: float, profit: float = 0, profit_percent: float = 0):
        self.last_message = f"{action} 成功"
        self.last_message_time = time.time()
        self.last_update_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        trade_queue.put((self.symbol, action, price, amount, self.last_update_time, profit, profit_percent))
        logging.info(f"记录交易: {self.symbol} - {action} at {price:.2f}, 金额: {amount:.2f}, 利润: {profit:.2f}")

    def check_open_position(self, current_price: float):
        if self.initial_price is None:
            self.reset_state(current_price)
        if current_price < self.lowest_price:
            self.lowest_price = current_price
        drop = (self.initial_price - current_price) / self.initial_price if self.initial_price else 0
        rebound = (current_price - self.lowest_price) / self.lowest_price if self.lowest_price else 0
        drop_condition = self.drop_percent == 0 or drop >= self.drop_percent / 100
        rebound_condition = self.rebound_percent == 0 or rebound >= self.rebound_percent / 100
        logging.info(f"{self.symbol} 开仓检查: 下跌 {drop*100:.2f}% (需 {self.drop_percent:.2f}%), 反弹 {rebound*100:.2f}% (需 {self.rebound_percent:.2f}%)")
        if drop_condition and rebound_condition:
            amount = self.initial_amount / current_price
            if self.is_test_mode:
                self.positions.append(Position(current_price, amount))
                self.last_entry_price = current_price
                self.lowest_price = current_price
                self.log_trade("开仓", current_price, self.initial_amount)
            else:
                order = self.exchange.create_market_buy_order(self.symbol.replace('-', '/'), amount)
                self.positions.append(Position(current_price, order['filled']))
                self.last_entry_price = current_price
                self.lowest_price = current_price
                self.log_trade("开仓", current_price, order['filled'] * current_price)

    def check_add_position(self, current_price: float):
        if not self.positions or self.add_position_count >= self.max_add_positions:
            return
        avg_cost = self.calculate_avg_cost()
        if current_price < self.lowest_price:
            self.lowest_price = current_price
        drop = (avg_cost - current_price) / avg_cost
        rebound = (current_price - self.lowest_price) / self.lowest_price if self.lowest_price != 0 else 0
        
        if self.advanced_add and self.add_position_count < len(self.advanced_add):
            add_config = self.advanced_add[self.add_position_count]
            drop_condition = drop >= add_config['drop'] / 100
            rebound_condition = rebound >= add_config['rebound'] / 100
            multiplier = add_config['multiplier'] / 100
            base_amount = sum(pos.amount for pos in self.positions) if add_config['by_total'] else self.initial_amount
        else:
            drop_condition = drop >= self.add_drop_percent / 100
            rebound_condition = rebound >= self.add_rebound_percent / 100
            multiplier = self.add_multiplier / 100
            base_amount = sum(pos.amount for pos in self.positions) if self.add_by_total else self.initial_amount

        if drop_condition and rebound_condition:
            add_amount = base_amount * multiplier / current_price
            if self.is_test_mode:
                self.positions.append(Position(current_price, add_amount))
                self.last_entry_price = current_price
                self.lowest_price = current_price
                self.add_position_count += 1
                self.log_trade(f"补仓 {self.add_position_count}", current_price, add_amount * current_price)
            else:
                order = self.exchange.create_limit_buy_order(self.symbol.replace('-', '/'), add_amount, current_price)
                if self.order_timeout > 0:
                    start_time = time.time()
                    while time.time() - start_time < self.order_timeout:
                        order_status = self.exchange.fetch_order(order['id'])
                        if order_status['status'] == 'closed':
                            break
                        time.sleep(1)
                    if order_status['status'] != 'closed':
                        self.exchange.cancel_order(order['id'])
                        order_status = self.exchange.fetch_order(order['id'])
                        self.last_message = f"补仓 {self.add_position_count + 1} 超时取消，部分成交: {order_status['filled']}"
                        self.last_message_time = time.time()
                    else:
                        self.log_trade(f"补仓 {self.add_position_count + 1}", current_price, order_status['filled'] * current_price)
                else:
                    order_status = self.exchange.fetch_order(order['id'])
                    while order_status['status'] != 'closed':
                        order_status = self.exchange.fetch_order(order['id'])
                        time.sleep(1)
                    self.log_trade(f"补仓 {self.add_position_count + 1}", current_price, order_status['filled'] * current_price)
                self.positions.append(Position(current_price, order_status['filled']))
                self.last_entry_price = current_price
                self.lowest_price = current_price
                self.add_position_count += 1

    def check_close_position(self, current_price: float):
        if not self.positions:
            return False
        avg_cost = self.calculate_avg_cost()
        profit_percent = self.calculate_profit_percent(current_price)
        rebound = (current_price - self.lowest_price) / self.lowest_price if self.lowest_price != 0 else 0
        profit_condition = profit_percent >= self.profit_target / 100
        rebound_condition = rebound >= self.profit_rebound / 100

        if profit_condition and rebound_condition:
            total_amount = sum(pos.amount for pos in self.positions)
            total_cost = sum(pos.entry_price * pos.amount for pos in self.positions)
            profit = current_price * total_amount - total_cost
            profit_percent = (profit / total_cost) * 100 if total_cost > 0 else 0
            if self.is_test_mode:
                self.log_trade("全部平仓", current_price, total_amount * current_price, profit, profit_percent)
                self.reset_state(current_price)
            else:
                self.exchange.create_market_sell_order(self.symbol.replace('-', '/'), total_amount)
                self.log_trade("全部平仓", current_price, total_amount * current_price, profit, profit_percent)
                self.reset_state(current_price)
            if not self.loop_execution:
                self.stop()
            return True
        return False

    def run(self):
        strat_id = id(self)
        if strat_id in running_strategies:
            logging.warning(f"{self.symbol} 已在运行，跳过重复启动")
            return
        self.running = True
        self.run_event.set()
        running_strategies[strat_id] = self
        logging.info(f"{self.symbol} 策略启动，ID: {strat_id}")
        update_websocket_subscriptions()
        while self.run_event.is_set():
            try:
                current_price = self.get_current_price()
                if self.last_price != current_price:
                    if not self.positions:
                        self.check_open_position(current_price)
                    else:
                        closed = self.check_close_position(current_price)
                        if closed and self.loop_execution:
                            self.check_open_position(current_price)
                        else:
                            self.check_add_position(current_price)
                    self.last_price = current_price
                    if self.last_message and self.last_message_time and (time.time() - self.last_message_time > 2):
                        self.last_message = ""
                    if not self.last_message and self.positions:
                        profit_percent = self.calculate_profit_percent(current_price)
                        self.last_message = f"价格变化：{profit_percent:.2f}%"
                self.last_update_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                time.sleep(2.5)
            except Exception as e:
                logging.error(f"策略 {self.symbol} 运行错误: {e}")
                time.sleep(2.5)
        self.running = False
        if strat_id in running_strategies:
            del running_strategies[strat_id]
        logging.info(f"{self.symbol} 策略停止，ID: {strat_id}")
        update_websocket_subscriptions()
        save_strategies()

    def stop(self):
        self.run_event.clear()
        self.running = False
        strat_id = id(self)
        if strat_id in running_strategies:
            del running_strategies[strat_id]
        save_strategies()

    def to_dict(self):
        return {
            'symbol': self.symbol,
            'is_test_mode': self.is_test_mode,
            'exchange_name': self.exchange_name,
            'api_key': self.api_key,
            'api_secret': self.api_secret,
            'password': self.password,
            'positions': [(pos.entry_price, pos.amount) for pos in self.positions],
            'initial_price': self.initial_price,
            'lowest_price': self.lowest_price,
            'last_entry_price': self.last_entry_price,
            'add_position_count': self.add_position_count,
            'params': self.params,
            'last_price': self.last_price,
            'last_message': self.last_message,
            'last_update_time': self.last_update_time,
            'last_message_time': self.last_message_time
        }

    @classmethod
    def from_dict(cls, data):
        strat = cls(
            exchange_name=data['exchange_name'],
            symbol=data['symbol'],
            api_key=data['api_key'],
            api_secret=data['api_secret'],
            password=data.get('password'),
            **data['params']
        )
        strat.positions = [Position(entry_price, amount) for entry_price, amount in data['positions']]
        strat.initial_price = data['initial_price']
        strat.lowest_price = data['lowest_price']
        strat.last_entry_price = data['last_entry_price']
        strat.add_position_count = data['add_position_count']
        strat.last_price = data['last_price']
        strat.last_message = data['last_message']
        strat.last_update_time = data['last_update_time']
        strat.last_message_time = data.get('last_message_time')
        return strat

def save_strategies():
    with open(STRATEGIES_FILE, 'wb') as f:
        pickle.dump([strat.to_dict() for strat in strategies], f)
    logging.info("策略保存至 data/strategies.pkl")

def load_strategies():
    global strategies
    if os.path.exists(STRATEGIES_FILE):
        with open(STRATEGIES_FILE, 'rb') as f:
            strategies_data = pickle.load(f)
            strategies = [TradingStrategy.from_dict(data) for data in strategies_data]
        logging.info(f"从 data/strategies.pkl 加载 {len(strategies)} 个策略")
    else:
        strategies = []
        logging.info("未找到 data/strategies.pkl，初始化为空策略列表")

def save_api_configs():
    with open(API_CONFIGS_FILE, 'wb') as f:
        pickle.dump(api_configs, f)
    logging.info("API 配置保存至 data/api_configs.pkl")

def load_api_configs():
    global api_configs
    if os.path.exists(API_CONFIGS_FILE):
        with open(API_CONFIGS_FILE, 'rb') as f:
            api_configs = pickle.load(f)
        logging.info(f"从 data/api_configs.pkl 加载 {len(api_configs)} 个 API 配置")
    else:
        api_configs = []
        logging.info("未找到 data/api_configs.pkl，初始化为空 API 配置")

def save_trades(trades):
    with open(TRADES_FILE, 'wb') as f:
        pickle.dump(trades, f)
    logging.info("交易记录保存至 data/trades.pkl")

def load_trades():
    if os.path.exists(TRADES_FILE):
        with open(TRADES_FILE, 'rb') as f:
            trades = pickle.load(f)
            logging.info(f"从 data/trades.pkl 加载 {len(trades)} 条交易记录")
            return trades
    logging.info("未找到 data/trades.pkl，初始化为空交易记录")
    return []

def on_message(ws, message):
    if not message:
        logging.warning("收到空 WebSocket 消息")
        return
    if message == "pong":
        logging.info("收到 WebSocket pong")
        return
    try:
        data = json.loads(message)
        logging.debug(f"WebSocket 收到消息: {message}")
        if 'arg' in data and 'data' in data and isinstance(data['data'], list):
            for item in data['data']:
                if 'instId' in item and 'last' in item:
                    symbol = item['instId']
                    price = float(item['last'])
                    latest_prices[symbol] = price
                    logging.info(f"WebSocket 更新 {symbol} 价格: {price}")
    except Exception as e:
        logging.error(f"WebSocket 消息处理错误: {e}")

def on_error(ws, error):
    logging.error(f"WebSocket 错误: {error}")

def on_close(ws, close_status_code, close_msg):
    global websocket_instance, websocket_thread_running
    websocket_instance = None
    websocket_thread_running = False
    logging.info(f"WebSocket 关闭: 状态码 {close_status_code}, 消息 {close_msg}")
    time.sleep(5)
    start_websocket_for_strategies()

def on_open(ws):
    global websocket_instance
    websocket_instance = ws
    logging.info("WebSocket 连接打开")
    update_websocket_subscriptions()

def update_websocket_subscriptions():
    global websocket_instance
    if websocket_instance is None:
        logging.warning("WebSocket 未连接，无法更新订阅")
        return
    symbols = [strat.symbol for strat in running_strategies.values() if strat.exchange_name == 'okx']
    try:
        if symbols:
            subscription = {"op": "subscribe", "args": [{"channel": "tickers", "instId": symbol} for symbol in symbols]}
            websocket_instance.send(json.dumps(subscription))
            logging.info(f"发送 WebSocket 订阅请求: {subscription}")
        else:
            logging.info("当前无运行的 OKX 策略，无需订阅")
    except Exception as e:
        logging.error(f"WebSocket 订阅更新失败: {e}")

def start_websocket_for_strategies():
    global websocket_instance, websocket_thread_running
    if websocket_instance is not None or websocket_thread_running:
        logging.info("WebSocket 已连接或线程运行中，无需重复启动")
        return
    ws_url = "wss://ws.okx.com:8443/ws/v5/public"
    ws = websocket.WebSocketApp(ws_url, on_message=on_message, on_error=on_error, on_close=on_close, on_open=on_open)
    websocket_thread_running = True
    threading.Thread(target=ws.run_forever, daemon=True).start()

def process_trade_queue():
    while True:
        try:
            with trade_lock:
                trades = []
                while not trade_queue.empty():
                    trades.append(trade_queue.get())
                if trades:
                    with sqlite3.connect(TRADES_DB) as conn:
                        c = conn.cursor()
                        c.executemany('''INSERT INTO trades (symbol, action, price, amount, timestamp, profit, profit_percent) 
                                         VALUES (?, ?, ?, ?, ?, ?, ?)''', trades)
                        conn.commit()
                        for trade in trades:
                            logging.info(f"[交易] {trade[1]}: {trade[0]} 价格 {trade[2]:.2f}, 金额: {trade[3]:.2f}, 利润: {trade[5]:.2f}")
                    all_trades = load_trades()
                    all_trades.extend(trades)
                    save_trades(all_trades)
            time.sleep(1)
        except Exception as e:
            logging.error(f"处理交易队列错误: {e}")
            time.sleep(1)

def fetch_usdt_pairs_sync(exchange_name: str, api_key: str, api_secret: str, password: str = None, is_test_mode: bool = True) -> List[str]:
    try:
        config = {
            'apiKey': api_key,
            'secret': api_secret,
            'enableRateLimit': True,
            'timeout': 30000,
            'options': {'defaultType': 'spot'},
            'headers': {'Content-Type': 'application/json', 'x-simulated-trading': '1' if is_test_mode else '0'}
        }
        if exchange_name == 'okx' and password:
            config['password'] = password
        exchange = getattr(ccxt, exchange_name)(config)
        markets = exchange.fetch_markets()
        usdt_pairs = [market['symbol'] for market in markets if market['quote'] == 'USDT' and market['type'] == 'spot']
        logging.info(f"成功加载 {exchange_name} 的 USDT 现货交易对: {len(usdt_pairs)} 个，第一对: {usdt_pairs[0] if usdt_pairs else '无'}")
        return sorted(usdt_pairs)
    except Exception as e:
        logging.error(f"同步获取交易对失败: {e}")
        return ['BTC/USDT', 'ETH/USDT', 'LTC/USDT', 'SUI/USDT']

def get_usdt_pairs(exchange_name: str, api_key: str, api_secret: str, password: str = None, is_test_mode: bool = True) -> List[str]:
    key = f"{exchange_name}_{api_key}_{'test' if is_test_mode else 'live'}"
    if key not in pairs_cache:
        pairs_cache[key] = fetch_usdt_pairs_sync(exchange_name, api_key, api_secret, password, is_test_mode)
    return pairs_cache[key]

def preload_pairs():
    for api in api_configs:
        key = f"{api['exchange']}_{api['api_key']}_{'test' if api.get('is_test_mode', True) else 'live'}"
        if key not in pairs_cache:
            pairs_cache[key] = fetch_usdt_pairs_sync(api['exchange'], api['api_key'], api['api_secret'], api.get('password'), api.get('is_test_mode', True))
    logging.info("交易对预加载完成")

app = Flask(__name__)
app.secret_key = 'your_secure_secret_key_here'
strategies = []
api_configs = []
last_params = {}

os.makedirs(DATA_DIR, exist_ok=True)

executor.submit(process_trade_queue)
threading.Thread(target=start_websocket_for_strategies, daemon=True).start()
preload_pairs()
load_strategies()
load_api_configs()

def init_db():
    with sqlite3.connect(TRADES_DB) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users 
                     (username TEXT PRIMARY KEY, password TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS trades 
                     (id INTEGER PRIMARY KEY, symbol TEXT, action TEXT, price REAL, amount REAL, 
                      timestamp TEXT, profit REAL, profit_percent REAL)''')
        hashed_pw = hashlib.sha256('password123'.encode()).hexdigest()
        c.execute('INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)', ('admin', hashed_pw))
        conn.commit()

@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        with sqlite3.connect(TRADES_DB) as conn:
            c = conn.cursor()
            c.execute('SELECT password FROM users WHERE username = ?', (username,))
            result = c.fetchone()
            if result and result[0] == password:
                session['username'] = username
                return redirect(url_for('index'))
        flash('用户名或密码错误')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'username' not in session:
        return redirect(url_for('login'))
    if not api_configs:
        flash('请先添加 API 配置')
        return redirect(url_for('api_settings'))
    usdt_pairs = {f"{api['exchange']}_{api['api_key']}": get_usdt_pairs(api['exchange'], api['api_key'], api['api_secret'], api.get('password'), api.get('is_test_mode', True)) for api in api_configs}
    if request.method == 'POST':
        try:
            api_id = request.form['api_id']
            api = next((a for a in api_configs if f"{a['exchange']}_{a['api_key']}" == api_id), None)
            if not api:
                flash('无效的 API 选择')
                return redirect(url_for('settings'))
            params = {
                'initial_amount': float(request.form['initial_amount']),
                'drop_percent': float(request.form['drop_percent']),
                'rebound_percent': float(request.form['rebound_percent']),
                'max_add_positions': int(request.form['max_add_positions']),
                'add_drop_percent': float(request.form['add_drop_percent']),
                'add_rebound_percent': float(request.form['add_rebound_percent']),
                'add_multiplier': float(request.form['add_multiplier']),
                'profit_target': float(request.form['profit_target']),
                'profit_rebound': float(request.form['profit_rebound']),
                'use_arbitrage': request.form.get('use_arbitrage') == 'on',
                'add_by_total': request.form.get('add_by_total') == 'on',
                'loop_execution': request.form.get('loop_execution') == 'on',
                'order_timeout': int(request.form.get('order_timeout', 0)) if request.form.get('use_order_timeout') == 'on' else 0,
                'is_test_mode': api.get('is_test_mode', True)
            }
            if request.form.get('use_advanced_add') == 'on':
                advanced_add = []
                for i in range(int(request.form['max_add_positions'])):
                    drop = request.form.get(f'add_drop_{i+1}')
                    rebound = request.form.get(f'add_rebound_{i+1}')
                    multiplier = request.form.get(f'add_multiplier_{i+1}')
                    if drop and rebound and multiplier:
                        advanced_add.append({
                            'drop': float(drop),
                            'rebound': float(rebound),
                            'multiplier': float(multiplier),
                            'by_total': request.form.get(f'add_type_{i+1}') == 'total'
                        })
                params['advanced_add'] = advanced_add
            else:
                params['advanced_add'] = []
            global strategies, last_params
            last_params = params.copy()
            last_params['symbol'] = request.form['symbol']
            strat = TradingStrategy(api['exchange'], request.form['symbol'], 
                                   api['api_key'], api['api_secret'], api.get('password'), **params)
            strategies.append(strat)
            save_strategies()
            if 'save_and_run' in request.form:
                executor.submit(strat.run)
                flash(f"已为 {request.form['symbol']} 添加并运行策略")
            else:
                flash(f"已为 {request.form['symbol']} 添加策略（默认停止运行）")
            return redirect(url_for('index'))
        except Exception as e:
            logging.error(f"保存策略错误: {e}")
            flash(f"保存策略失败: {str(e)}")
            return redirect(url_for('settings'))
    return render_template('settings.html', api_configs=api_configs, last_params=last_params, usdt_pairs=usdt_pairs)

@app.route('/edit_strategy/<strat_id>', methods=['GET', 'POST'])
def edit_strategy(strat_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    strat_index = next((i for i, s in enumerate(strategies) if str(id(s)) == strat_id), None)
    if strat_index is None:
        logging.error(f"策略 {strat_id} 不存在")
        flash('策略不存在')
        return redirect(url_for('index'))
    strat = strategies[strat_index]
    usdt_pairs = {f"{api['exchange']}_{api['api_key']}": get_usdt_pairs(api['exchange'], api['api_key'], api['api_secret'], api.get('password'), api.get('is_test_mode', True)) for api in api_configs}
    if request.method == 'POST':
        try:
            logging.info(f"开始编辑策略 {strat.symbol}, ID: {strat_id}")
            api_id = request.form['api_id']
            api = next((a for a in api_configs if f"{a['exchange']}_{a['api_key']}" == api_id), None)
            if not api:
                logging.error("无效的 API 选择")
                flash('无效的 API 选择')
                return redirect(url_for('edit_strategy', strat_id=strat_id))
            
            # 保存旧状态
            old_data = strat.to_dict()
            was_running = strat.running
            if was_running:
                logging.info(f"停止运行中的策略 {strat.symbol}")
                strat.stop()
                time.sleep(2)  # 增加等待时间，确保线程完全停止
                if id(strat) in running_strategies:
                    del running_strategies[id(strat)]
                    logging.info(f"从 running_strategies 移除 {strat.symbol}")

            # 更新参数
            params = {
                'initial_amount': float(request.form['initial_amount']),
                'drop_percent': float(request.form['drop_percent']),
                'rebound_percent': float(request.form['rebound_percent']),
                'max_add_positions': int(request.form['max_add_positions']),
                'add_drop_percent': float(request.form['add_drop_percent']),
                'add_rebound_percent': float(request.form['add_rebound_percent']),
                'add_multiplier': float(request.form['add_multiplier']),
                'profit_target': float(request.form['profit_target']),
                'profit_rebound': float(request.form['profit_rebound']),
                'use_arbitrage': request.form.get('use_arbitrage') == 'on',
                'add_by_total': request.form.get('add_by_total') == 'on',
                'loop_execution': request.form.get('loop_execution') == 'on',
                'order_timeout': int(request.form.get('order_timeout', 0)) if request.form.get('use_order_timeout') == 'on' else 0,
                'is_test_mode': api.get('is_test_mode', True),
                'positions': old_data['positions'],
                'add_position_count': old_data['add_position_count'],
                'initial_open_price': old_data['initial_open_price'],
                'initial_price': old_data['initial_price'],
                'lowest_price': old_data['lowest_price'],
                'last_entry_price': old_data['last_entry_price']
            }
            if request.form.get('use_advanced_add') == 'on':
                advanced_add = []
                for i in range(int(request.form['max_add_positions'])):
                    drop = request.form.get(f'add_drop_{i+1}')
                    rebound = request.form.get(f'add_rebound_{i+1}')
                    multiplier = request.form.get(f'add_multiplier_{i+1}')
                    if drop and rebound and multiplier:
                        advanced_add.append({
                            'drop': float(drop),
                            'rebound': float(rebound),
                            'multiplier': float(multiplier),
                            'by_total': request.form.get(f'add_type_{i+1}') == 'total'
                        })
                params['advanced_add'] = advanced_add
            else:
                params['advanced_add'] = []

            # 创建新策略
            new_strat = TradingStrategy(
                api['exchange'], request.form['symbol'], 
                api['api_key'], api['api_secret'], api.get('password'), **params
            )
            # 替换旧策略
            strategies[strat_index] = new_strat
            logging.info(f"策略 {new_strat.symbol} 已更新至 strategies 列表，位置: {strat_index}")
            
            # 保存并重新加载
            save_strategies()
            load_strategies()  # 确保从磁盘加载最新状态
            logging.info(f"策略列表重新加载，当前总数: {len(strategies)}")

            # 如果之前在运行，则重启
            if was_running:
                for i, s in enumerate(strategies):
                    if s.symbol == new_strat.symbol and s.api_key == new_strat.api_key:  # 用 symbol 和 api_key 匹配
                        executor.submit(s.run)
                        logging.info(f"策略 {s.symbol} 修改后重新启动")
                        break

            flash(f"已修改 {new_strat.symbol} 的策略")
            return redirect(url_for('index'))
        except Exception as e:
            logging.error(f"修改策略 {strat_id} 失败: {str(e)}", exc_info=True)
            flash(f"修改策略失败: {str(e)}")
            return redirect(url_for('edit_strategy', strat_id=strat_id))
    return render_template('edit_strategy.html', strat=strat, api_configs=api_configs, usdt_pairs=usdt_pairs)

@app.route('/api_settings', methods=['GET', 'POST'])
def api_settings():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        if 'test_connection' in request.form:
            try:
                exchange_name = request.form['exchange']
                api_key = request.form['api_key']
                api_secret = request.form['api_secret']
                password = request.form.get('password', '')
                is_test_mode = request.form.get('is_test_mode') == 'on'
                config = {
                    'apiKey': api_key,
                    'secret': api_secret,
                    'enableRateLimit': True,
                    'options': {'defaultType': 'spot'},
                    'timeout': 30000,
                    'headers': {'Content-Type': 'application/json', 'x-simulated-trading': '1' if is_test_mode else '0'}
                }
                if exchange_name == 'okx' and password:
                    config['password'] = password
                exchange = getattr(ccxt, exchange_name)(config)
                exchange.fetch_ticker('BTC/USDT')
                flash(f"API 连接测试成功: {exchange_name} {'模拟账户' if is_test_mode else '实盘账户'}")
            except Exception as e:
                logging.error(f"API 测试连接失败: {e}")
                flash(f"API 连接测试失败: {str(e)}")
            return redirect(url_for('api_settings'))
        else:
            api_configs.append({
                'name': request.form['name'],
                'exchange': request.form['exchange'],
                'api_key': request.form['api_key'],
                'api_secret': request.form['api_secret'],
                'password': request.form.get('password', ''),
                'is_test_mode': request.form.get('is_test_mode') == 'on'
            })
            save_api_configs()
            preload_pairs()
            flash('API 配置已添加')
            return redirect(url_for('api_settings'))
    return render_template('api_settings.html', api_configs=api_configs)

@app.route('/delete_api/<api_id>', methods=['GET', 'POST'])
def delete_api(api_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'GET':
        api = next((a for a in api_configs if f"{a['exchange']}_{a['api_key']}" == api_id), None)
        if not api:
            flash('API 配置不存在')
            return redirect(url_for('api_settings'))
        return render_template('confirm_delete_api.html', api=api)
    if request.method == 'POST':
        try:
            api = next((a for a in api_configs if f"{a['exchange']}_{a['api_key']}" == api_id), None)
            if api:
                api_configs.remove(api)
                key = f"{api['exchange']}_{api['api_key']}"
                if key in pairs_cache:
                    del pairs_cache[key]
                save_api_configs()
                flash(f"已删除 API 配置: {api['name']}")
            else:
                flash('API 配置不存在')
            return redirect(url_for('api_settings'))
        except Exception as e:
            logging.error(f"删除 API 配置错误: {e}")
            flash(f"删除 API 配置失败: {str(e)}")
            return redirect(url_for('api_settings'))

@app.route('/trades', methods=['GET', 'POST'])
def trades():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))
    if per_page not in [20, 50, 100]:
        per_page = 20
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')

    where_clause = ''
    params = []
    if start_date and end_date:
        try:
            start_dt = datetime.strptime(start_date, '%Y-%m-%d')
            end_dt = datetime.strptime(end_date, '%Y-%m-%d')
            if start_dt > end_dt:
                flash('开始日期不能晚于结束日期')
                start_date, end_date = '', ''
            else:
                start_time = start_dt.strftime('%Y-%m-%d 00:00:00')
                end_time = end_dt.strftime('%Y-%m-%d 23:59:59')
                where_clause = 'WHERE timestamp >= ? AND timestamp <= ?'
                params.extend([start_time, end_time])
                logging.debug(f"交易记录查询: start_time={start_time}, end_time={end_time}")
        except ValueError:
            flash('日期格式错误，请使用 YYYY-MM-DD')
            start_date, end_date = ''

    with sqlite3.connect(TRADES_DB) as conn:
        c = conn.cursor()
        total_query = f'SELECT COUNT(*) FROM trades {where_clause}'
        c.execute(total_query, params)
        total_records = c.fetchone()[0]
        logging.debug(f"总记录数: {total_records}")

    total_pages = (total_records + per_page - 1) // per_page
    offset = (page - 1) * per_page

    with sqlite3.connect(TRADES_DB) as conn:
        c = conn.cursor()
        query = f'SELECT * FROM trades {where_clause} ORDER BY timestamp DESC LIMIT ? OFFSET ?'
        c.execute(query, params + [per_page, offset])
        trade_records = c.fetchall()
        logging.debug(f"查询结果记录数: {len(trade_records)}")

    return render_template('trades.html', trades=trade_records, page=page, per_page=per_page, 
                          total_pages=total_pages, start_date=start_date, end_date=end_date)

@app.route('/profits', methods=['GET', 'POST'])
def profits():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')

    where_clause = ''
    params = []
    if start_date and end_date:
        try:
            start_dt = datetime.strptime(start_date, '%Y-%m-%d')
            end_dt = datetime.strptime(end_date, '%Y-%m-%d')
            if start_dt > end_dt:
                flash('开始日期不能晚于结束日期')
                start_date, end_date = '', ''
            else:
                start_time = start_dt.strftime('%Y-%m-%d 00:00:00')
                end_time = end_dt.strftime('%Y-%m-%d 23:59:59')
                where_clause = 'AND timestamp >= ? AND timestamp <= ?'
                params = [start_time, end_time]
                logging.debug(f"利润统计查询: start_time={start_time}, end_time={end_time}")
        except ValueError:
            flash('日期格式错误，请使用 YYYY-MM-DD')
            start_date, end_date = ''

    try:
        with sqlite3.connect(TRADES_DB) as conn:
            c = conn.cursor()
            query = f"""
                SELECT 
                    'USDT' AS currency,
                    strftime('%Y-%m-%d', timestamp) AS date,
                    SUM(profit) AS daily_profit,
                    COUNT(*) AS close_count
                FROM trades 
                WHERE action LIKE '%平仓' AND profit IS NOT NULL {where_clause}
                GROUP BY strftime('%Y-%m-%d', timestamp)
                ORDER BY date DESC
            """
            c.execute(query, params)
            daily_profits = c.fetchall() or []
            logging.debug(f"利润统计查询结果: {daily_profits}")
    except Exception as e:
        logging.error(f"利润统计查询错误: {e}")
        daily_profits = []

    return render_template('profits.html', daily_profits=daily_profits, start_date=start_date, end_date=end_date)

@app.route('/assets', methods=['GET', 'POST'])
def assets():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        api_id = request.form['api_id']
        api = next((a for a in api_configs if f"{a['exchange']}_{a['api_key']}" == api_id), None)
        if not api:
            flash('API 配置不存在')
            return redirect(url_for('assets'))
        try:
            config = {
                'apiKey': api['api_key'],
                'secret': api['api_secret'],
                'enableRateLimit': True,
                'options': {'defaultType': 'spot'},
                'timeout': 30000,
                'headers': {'Content-Type': 'application/json', 'x-simulated-trading': '1' if api.get('is_test_mode', True) else '0'}
            }
            if api['exchange'] == 'okx' and api.get('password'):
                config['password'] = api['password']
            exchange = getattr(ccxt, api['exchange'])(config)
            balance = exchange.fetch_balance()
            assets = {currency: info['free'] for currency, info in balance['free'].items() if float(info['free']) > 0}
            return render_template('assets.html', api_configs=api_configs, selected_api=api_id, assets=assets)
        except Exception as e:
            logging.error(f"资产查询错误: {e}")
            flash(f"资产查询失败: {str(e)}")
            return redirect(url_for('assets'))
    return render_template('assets.html', api_configs=api_configs, selected_api=None, assets=None)

@app.route('/start/<strat_id>')
def start_strategy(strat_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    strat = next((s for s in strategies if str(id(s)) == strat_id), None)
    if strat and not strat.running:
        executor.submit(strat.run)
        flash(f"已启动 {strat.symbol} 的策略")
    elif strat and strat.running:
        flash(f"{strat.symbol} 已在运行")
    else:
        flash('策略不存在')
    return redirect(url_for('index'))

@app.route('/pause/<strat_id>')
def pause_strategy(strat_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    strat = next((s for s in strategies if str(id(s)) == strat_id), None)
    if strat and strat.running:
        strat.stop()
        time.sleep(1)
        flash(f"已暂停 {strat.symbol} 的策略")
    elif strat and not strat.running:
        flash(f"{strat.symbol} 已停止")
    else:
        flash('策略不存在')
    return redirect(url_for('index'))

@app.route('/delete/<strat_id>', methods=['GET', 'POST'])
def delete_strategy(strat_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    strat = next((s for s in strategies if str(id(s)) == strat_id), None)
    if not strat:
        logging.error(f"策略 {strat_id} 不存在")
        flash('策略不存在')
        return redirect(url_for('index'))
    
    if request.method == 'GET':
        return render_template('confirm_delete.html', strat=strat)
    
    if request.method == 'POST':
        try:
            logging.info(f"开始删除策略 {strat.symbol}，ID: {strat_id}")
            retain_positions = request.form.get('retain_positions') == 'yes'
            if strat.running:
                strat.stop()
                time.sleep(1)
                logging.info(f"策略 {strat.symbol} 已停止运行")
            if not retain_positions and strat.positions:
                current_price = strat.get_current_price()
                total_amount = sum(pos.amount for pos in strat.positions)
                total_cost = sum(pos.entry_price * pos.amount for pos in strat.positions)
                profit = current_price * total_amount - total_cost
                profit_percent = (profit / total_cost) * 100 if total_cost > 0 else 0
                strat.log_trade("删除前平仓", current_price, total_amount * current_price, profit, profit_percent)
                logging.info(f"策略 {strat.symbol} 持仓已卖出")
            strategies.remove(strat)
            if id(strat) in running_strategies:
                del running_strategies[id(strat)]
            save_strategies()
            update_websocket_subscriptions()
            logging.info(f"策略 {strat.symbol} 删除完成，持仓{'保留' if retain_positions else '已卖出'}")
            flash(f"已删除 {strat.symbol} 的策略，持仓{'保留' if retain_positions else '已卖出'}")
            return redirect(url_for('index'))
        except Exception as e:
            logging.error(f"删除策略 {strat_id} 错误: {e}")
            flash(f"删除策略失败: {str(e)}")
            return redirect(url_for('index'))

@app.route('/data')
def get_data():
    try:
        status = []
        total_closed_profit = 0
        total_positions_usdt = 0
        total_open_profit = 0
        for strat in strategies:
            current_price = strat.get_current_price()
            expected_profit = strat.calculate_profit(current_price)
            closed_profit = strat.calculate_closed_profit()
            total_closed_profit += closed_profit
            total_positions_usdt += sum(pos.amount * current_price for pos in strat.positions)
            total_open_profit += expected_profit
            mode = '模拟交易' if strat.is_test_mode else '实盘交易'
            purchase_amount, purchase_cost = strat.get_purchase_details()
            color_class = 'text-success' if strat.running else 'text-warning'
            status.append({
                'id': str(id(strat)),
                'symbol': strat.symbol,
                'initial_open_price': strat.initial_open_price or current_price,
                'add_status': f"{strat.add_position_count}/{strat.max_add_positions}",
                'current_price': current_price,
                'avg_buy_price': strat.calculate_avg_cost(),
                'purchase_details': f"{purchase_amount:.4f}/{purchase_cost:.2f}",
                'expected_profit': expected_profit,
                'closed_profit': closed_profit,
                'last_message': strat.last_message,
                'last_update_time': strat.last_update_time,
                'running': strat.running,
                'color_class': color_class
            })
        strategies_html = "".join(
            f"""
                <tr>
                    <td><input type="checkbox" name="strategy_ids" value="{s['id']}"></td>
                    <td class="{s['color_class']}">{s['symbol']}</td>
                    <td>{s['initial_open_price']:.6f}</td>
                    <td>{s['add_status']}</td>
                    <td>{s['current_price']:.6f}</td>
                    <td>{s['avg_buy_price']:.6f}</td>
                    <td>{s['purchase_details']}</td>
                    <td>{s['expected_profit']:.2f}</td>
                    <td>{s['closed_profit']:.2f}</td>
                    <td>{s['last_message']} {s['last_update_time']}</td>
                </tr>
            """ for s in status
        )
        summary_html = f"""
            <p><strong>利润合计 (USDT):</strong> {total_closed_profit:.2f} 
               <strong>持仓总量 (USDT):</strong> {total_positions_usdt:.2f} 
               <strong>持仓盈亏 (USDT):</strong> {total_open_profit:.2f}</p>
        """
        return jsonify({'strategies': strategies_html, 'summary': summary_html})
    except Exception as e:
        logging.error(f"获取数据错误: {e}")
        return jsonify({'strategies': '', 'summary': ''})

# HTML 模板
login_html = """
<!DOCTYPE html>
<html>
<head>
    <title>登录</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-4">
                <div class="card">
                    <div class="card-body">
                        <h2 class="card-title text-center">登录</h2>
                        {% with messages = get_flashed_messages() %}
                            {% if messages %}
                                {% for message in messages %}
                                    <div class="alert alert-danger">{{ message }}</div>
                                {% endfor %}
                            {% endif %}
                        {% endwith %}
                        <form method="post">
                            <div class="mb-3">
                                <label class="form-label">用户名</label>
                                <input type="text" name="username" class="form-control" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">密码</label>
                                <input type="password" name="password" class="form-control" required>
                            </div>
                            <button type="submit" class="btn btn-primary w-100">登录</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
"""

index_html = """
<!DOCTYPE html>
<html>
<head>
    <title>量化交易管理</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .table-container {
            max-height: 400px;
            overflow-y: auto;
        }
        .summary-footer {
            position: fixed;
            bottom: 0;
            width: 100%;
            background-color: #f8f9fa;
            padding: 10px;
            text-align: center;
        }
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .btn-group {
            margin-left: 10px;
        }
    </style>
    <script>
        let selectedStrategies = new Set();

        function updateData() {
            fetch('/data')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('strategy-table').innerHTML = data.strategies;
                    document.getElementById('summary').innerHTML = data.summary;
                    document.querySelectorAll('input[name="strategy_ids"]').forEach(checkbox => {
                        if (selectedStrategies.has(checkbox.value)) {
                            checkbox.checked = true;
                        }
                        checkbox.addEventListener('change', function() {
                            if (this.checked) {
                                selectedStrategies.add(this.value);
                            } else {
                                selectedStrategies.delete(this.value);
                            }
                        });
                    });
                });
        }

        setInterval(updateData, 2000);
        window.onload = updateData;

        function performAction(action) {
            if (selectedStrategies.size === 0) {
                alert('请先选择一个策略');
                return;
            }
            const stratId = Array.from(selectedStrategies)[0];
            window.location.href = `/${action}/${stratId}`;
        }
    </script>
</head>
<body class="bg-light">
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="#">量化交易</a>
            <div class="navbar-nav">
                <a class="nav-link" href="{{ url_for('settings') }}">添加策略</a>
                <a class="nav-link" href="{{ url_for('api_settings') }}">API 配置</a>
                <a class="nav-link" href="{{ url_for('trades') }}">交易记录</a>
                <a class="nav-link" href="{{ url_for('profits') }}">利润统计</a>
                <a class="nav-link" href="{{ url_for('assets') }}">资产查询</a>
                <a class="nav-link" href="{{ url_for('logout') }}">退出</a>
            </div>
        </div>
    </nav>
    <div class="container mt-4">
        <h3>欢迎, {{ session['username'] }}</h3>
        <div class="card mt-3">
            <div class="card-header">
                <span>当前策略状态</span>
                <div class="btn-group">
                    <button class="btn btn-success btn-sm" onclick="performAction('start')">运行</button>
                    <button class="btn btn-warning btn-sm" onclick="performAction('pause')">暂停</button>
                    <button class="btn btn-primary btn-sm" onclick="performAction('edit_strategy')">修改</button>
                    <button class="btn btn-danger btn-sm" onclick="performAction('delete')">删除</button>
                </div>
            </div>
            <div class="card-body table-container">
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>选择</th>
                            <th>交易对</th>
                            <th>参照价格</th>
                            <th>补仓情况</th>
                            <th>最新价格</th>
                            <th>买入均价</th>
                            <th>购买详情</th>
                            <th>预期利润</th>
                            <th>累计利润</th>
                            <th>最后消息</th>
                        </tr>
                    </thead>
                    <tbody id="strategy-table"></tbody>
                </table>
            </div>
        </div>
    </div>
    <div class="summary-footer" id="summary"></div>
</body>
</html>
"""

settings_html = """
<!DOCTYPE html>
<html>
<head>
    <title>添加策略</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script>
        function toggleAdvancedAdd() {
            var useAdvanced = document.getElementById('use_advanced_add');
            var advancedAdd = document.getElementById('advanced_add');
            var maxAddPositions = document.getElementById('max_add_positions').value;
            if (useAdvanced.checked) {
                advancedAdd.style.display = 'block';
                advancedAdd.innerHTML = '';
                for (var i = 1; i <= maxAddPositions; i++) {
                    advancedAdd.innerHTML += `
                        <h5>补仓 ${i}</h5>
                        <div class="mb-3">
                            <label class="form-label">下跌%</label>
                            <input type="number" name="add_drop_${i}" class="form-control" value="${i == 1 ? 0.3 : ''}" step="0.01" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">回调%</label>
                            <input type="number" name="add_rebound_${i}" class="form-control" value="${i == 1 ? 0.01 : ''}" step="0.01" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">补仓比例%</label>
                            <input type="number" name="add_multiplier_${i}" class="form-control" value="" step="0.01" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">补仓类型</label>
                            <select name="add_type_${i}" class="form-select">
                                <option value="initial">按买入金额%</option>
                                <option value="total">按持仓资产%</option>
                            </select>
                        </div>
                    `;
                }
            } else {
                advancedAdd.style.display = 'none';
            }
        }
        function toggleTimeout() {
            var useTimeout = document.getElementById('use_order_timeout');
            var timeoutInput = document.getElementById('order_timeout_input');
            timeoutInput.style.display = useTimeout.checked ? 'block' : 'none';
        }
        window.onload = function() {
            document.getElementById('use_advanced_add').addEventListener('change', toggleAdvancedAdd);
            document.getElementById('max_add_positions').addEventListener('change', toggleAdvancedAdd);
            document.getElementById('use_order_timeout').addEventListener('change', toggleTimeout);
            toggleAdvancedAdd();
            toggleTimeout();
        };
    </script>
</head>
<body class="bg-light">
    <div class="container mt-4">
        <h3>添加交易策略</h3>
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                {% for message in messages %}
                    <div class="alert alert-info">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <div class="card">
            <div class="card-body">
                <form method="post">
                    <div class="mb-3">
                        <label class="form-label">选择 API</label>
                        <select name="api_id" class="form-select" required>
                            {% for api in api_configs %}
                                <option value="{{ api['exchange'] }}_{{ api['api_key'] }}" {% if last_params.get('api_id') == api['exchange'] + '_' + api['api_key'] %}selected{% endif %}>
                                    {{ api['name'] }} ({{ api['exchange'] }} - {{ api['api_key'][:4] }}...)
                                </option>
                            {% endfor %}
                        </select>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">交易对</label>
                        <select name="symbol" class="form-select" required>
                            {% for api_id, pairs in usdt_pairs.items() %}
                                {% if api_id == last_params.get('api_id') or not last_params.get('api_id') and loop.first %}
                                    {% for pair in pairs %}
                                        <option value="{{ pair }}" {% if last_params.get('symbol') == pair %}selected{% endif %}>{{ pair }}</option>
                                    {% endfor %}
                                {% endif %}
                            {% endfor %}
                        </select>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">首仓金额</label>
                        <input type="number" name="initial_amount" class="form-control" value="{{ last_params.get('initial_amount', 100) }}" step="0.01" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">初始下跌%</label>
                        <input type="number" name="drop_percent" class="form-control" value="{{ last_params.get('drop_percent', 10) }}" step="0.01" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">初始反弹%</label>
                        <input type="number" name="rebound_percent" class="form-control" value="{{ last_params.get('rebound_percent', 5) }}" step="0.01" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">最大补仓次数</label>
                        <input type="number" name="max_add_positions" id="max_add_positions" class="form-control" value="{{ last_params.get('max_add_positions', 2) }}" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">默认补仓下跌%</label>
                        <input type="number" name="add_drop_percent" class="form-control" value="{{ last_params.get('add_drop_percent', 0.3) }}" step="0.01" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">默认补仓反弹%</label>
                        <input type="number" name="add_rebound_percent" class="form-control" value="{{ last_params.get('add_rebound_percent', 0.01) }}" step="0.01" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">默认补仓比例%</label>
                        <input type="number" name="add_multiplier" class="form-control" value="{{ last_params.get('add_multiplier', 50) }}" step="0.01" required>
                    </div>
                    <div class="mb-3 form-check">
                        <input type="checkbox" name="use_advanced_add" id="use_advanced_add" class="form-check-input" {% if last_params.get('advanced_add') %}checked{% endif %}>
                        <label class="form-check-label" for="use_advanced_add">启用高级补仓</label>
                    </div>
                    <div id="advanced_add" style="display: none;"></div>
                    <div class="mb-3">
                        <label class="form-label">盈利目标%</label>
                        <input type="number" name="profit_target" class="form-control" value="{{ last_params.get('profit_target', 10) }}" step="0.01" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">盈利回调%</label>
                        <input type="number" name="profit_rebound" class="form-control" value="{{ last_params.get('profit_rebound', 2) }}" step="0.01" required>
                    </div>
                    <div class="mb-3 form-check">
                        <input type="checkbox" name="use_arbitrage" class="form-check-input" id="use_arbitrage" {% if last_params.get('use_arbitrage', True) %}checked{% endif %}>
                        <label class="form-check-label" for="use_arbitrage">补仓单套利</label>
                    </div>
                    <div class="mb-3 form-check">
                        <input type="checkbox" name="add_by_total" class="form-check-input" id="add_by_total" {% if last_params.get('add_by_total', False) %}checked{% endif %}>
                        <label class="form-check-label" for="add_by_total">默认按总持仓补仓</label>
                    </div>
                    <div class="mb-3 form-check">
                        <input type="checkbox" name="loop_execution" class="form-check-input" id="loop_execution" {% if last_params.get('loop_execution', False) %}checked{% endif %}>
                        <label class="form-check-label" for="loop_execution">是否循环执行</label>
                    </div>
                    <div class="mb-3 form-check">
                        <input type="checkbox" name="use_order_timeout" id="use_order_timeout" class="form-check-input" {% if last_params.get('order_timeout', 0) > 0 %}checked{% endif %}>
                        <label class="form-check-label" for="use_order_timeout">启用下单超时</label>
                    </div>
                    <div id="order_timeout_input" style="display: none;">
                        <div class="mb-3">
                            <label class="form-label">下单超时（秒）</label>
                            <input type="number" name="order_timeout" class="form-control" value="{{ last_params.get('order_timeout', 60) }}" required>
                        </div>
                    </div>
                    <div class="mt-3">
                        <button type="submit" name="save" class="btn btn-primary">保存</button>
                        <button type="submit" name="save_and_run" class="btn btn-success">保存并运行</button>
                        <a href="{{ url_for('index') }}" class="btn btn-secondary">返回</a>
                    </div>
                </form>
            </div>
        </div>
    </div>
</body>
</html>
"""

edit_strategy_html = """
<!DOCTYPE html>
<html>
<head>
    <title>修改策略</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script>
        function toggleAdvancedAdd() {
            var useAdvanced = document.getElementById('use_advanced_add');
            var advancedAdd = document.getElementById('advanced_add');
            var maxAddPositions = document.getElementById('max_add_positions').value;
            if (useAdvanced.checked) {
                advancedAdd.style.display = 'block';
                advancedAdd.innerHTML = '';
                for (var i = 1; i <= maxAddPositions; i++) {
                    advancedAdd.innerHTML += `
                        <h5>补仓 ${i}</h5>
                        <div class="mb-3">
                            <label class="form-label">下跌%</label>
                            <input type="number" name="add_drop_${i}" id="add_drop_${i}" class="form-control" value="${document.getElementById('add_drop_' + i)?.value || ''}" step="0.01" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">回调%</label>
                            <input type="number" name="add_rebound_${i}" id="add_rebound_${i}" class="form-control" value="${document.getElementById('add_rebound_' + i)?.value || ''}" step="0.01" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">补仓比例%</label>
                            <input type="number" name="add_multiplier_${i}" id="add_multiplier_${i}" class="form-control" value="${document.getElementById('add_multiplier_' + i)?.value || ''}" step="0.01" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">补仓类型</label>
                            <select name="add_type_${i}" id="add_type_${i}" class="form-select">
                                <option value="initial" ${document.getElementById('add_type_' + i)?.value == 'initial' ? 'selected' : ''}>按买入金额%</option>
                                <option value="total" ${document.getElementById('add_type_' + i)?.value == 'total' ? 'selected' : ''}>按持仓资产%</option>
                            </select>
                        </div>
                    `;
                }
            } else {
                advancedAdd.style.display = 'none';
            }
        }
        function toggleTimeout() {
            var useTimeout = document.getElementById('use_order_timeout');
            var timeoutInput = document.getElementById('order_timeout_input');
            timeoutInput.style.display = useTimeout.checked ? 'block' : 'none';
        }
        window.onload = function() {
            document.getElementById('use_advanced_add').addEventListener('change', toggleAdvancedAdd);
            document.getElementById('max_add_positions').addEventListener('change', toggleAdvancedAdd);
            document.getElementById('use_order_timeout').addEventListener('change', toggleTimeout);
            toggleAdvancedAdd();
            toggleTimeout();
        };
    </script>
</head>
<body class="bg-light">
    <div class="container mt-4">
        <h3>修改策略 - {{ strat.symbol }}</h3>
        <div class="card">
            <div class="card-body">
                <form method="post">
                    <div class="mb-3">
                        <label class="form-label">选择 API</label>
                        <select name="api_id" class="form-select" required>
                            {% for api in api_configs %}
                                <option value="{{ api['exchange'] }}_{{ api['api_key'] }}" {% if strat.exchange_name == api['exchange'] and strat.api_key == api['api_key'] %}selected{% endif %}>
                                    {{ api['name'] }} ({{ api['exchange'] }} - {{ api['api_key'][:4] }}...)
                                </option>
                            {% endfor %}
                        </select>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">交易对</label>
                        <select name="symbol" class="form-select" required>
                            {% for api_id, pairs in usdt_pairs.items() %}
                                {% if api_id == strat.exchange_name + '_' + strat.api_key %}
                                    {% for pair in pairs %}
                                        <option value="{{ pair }}" {% if strat.symbol == pair.replace('/', '-') %}selected{% endif %}>{{ pair }}</option>
                                    {% endfor %}
                                {% endif %}
                            {% endfor %}
                        </select>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">首仓金额</label>
                        <input type="number" name="initial_amount" class="form-control" value="{{ strat.initial_amount }}" step="0.01" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">初始下跌%</label>
                        <input type="number" name="drop_percent" class="form-control" value="{{ strat.drop_percent }}" step="0.01" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">初始反弹%</label>
                        <input type="number" name="rebound_percent" class="form-control" value="{{ strat.rebound_percent }}" step="0.01" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">最大补仓次数</label>
                        <input type="number" name="max_add_positions" id="max_add_positions" class="form-control" value="{{ strat.max_add_positions }}" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">默认补仓下跌%</label>
                        <input type="number" name="add_drop_percent" class="form-control" value="{{ strat.add_drop_percent }}" step="0.01" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">默认补仓反弹%</label>
                        <input type="number" name="add_rebound_percent" class="form-control" value="{{ strat.add_rebound_percent }}" step="0.01" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">默认补仓比例%</label>
                        <input type="number" name="add_multiplier" class="form-control" value="{{ strat.add_multiplier }}" step="0.01" required>
                    </div>
                    <div class="mb-3 form-check">
                        <input type="checkbox" name="use_advanced_add" id="use_advanced_add" class="form-check-input" {% if strat.advanced_add %}checked{% endif %}>
                        <label class="form-check-label" for="use_advanced_add">启用高级补仓</label>
                    </div>
                    <div id="advanced_add" style="display: none;">
                        {% for i in range(strat.max_add_positions) %}
                            {% set add = strat.advanced_add[i] if i < strat.advanced_add|length else {'drop': '', 'rebound': '', 'multiplier': '', 'by_total': False} %}
                            <h5>补仓 {{ i + 1 }}</h5>
                            <div class="mb-3">
                                <label class="form-label">下跌%</label>
                                <input type="number" name="add_drop_{{ i + 1 }}" id="add_drop_{{ i + 1 }}" class="form-control" value="{{ add.drop }}" step="0.01" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">回调%</label>
                                <input type="number" name="add_rebound_{{ i + 1 }}" id="add_rebound_{{ i + 1 }}" class="form-control" value="{{ add.rebound }}" step="0.01" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">补仓比例%</label>
                                <input type="number" name="add_multiplier_{{ i + 1 }}" id="add_multiplier_{{ i + 1 }}" class="form-control" value="{{ add.multiplier }}" step="0.01" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">补仓类型</label>
                                <select name="add_type_{{ i + 1 }}" id="add_type_{{ i + 1 }}" class="form-select">
                                    <option value="initial" {% if not add.by_total %}selected{% endif %}>按买入金额%</option>
                                    <option value="total" {% if add.by_total %}selected{% endif %}>按持仓资产%</option>
                                </select>
                            </div>
                        {% endfor %}
                    </div>
                    <div class="mb-3">
                        <label class="form-label">盈利目标%</label>
                        <input type="number" name="profit_target" class="form-control" value="{{ strat.profit_target }}" step="0.01" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">盈利回调%</label>
                        <input type="number" name="profit_rebound" class="form-control" value="{{ strat.profit_rebound }}" step="0.01" required>
                    </div>
                    <div class="mb-3 form-check">
                        <input type="checkbox" name="use_arbitrage" class="form-check-input" id="use_arbitrage" {% if strat.use_arbitrage %}checked{% endif %}>
                        <label class="form-check-label" for="use_arbitrage">补仓单套利</label>
                    </div>
                    <div class="mb-3 form-check">
                        <input type="checkbox" name="add_by_total" class="form-check-input" id="add_by_total" {% if strat.add_by_total %}checked{% endif %}>
                        <label class="form-check-label" for="add_by_total">默认按总持仓补仓</label>
                    </div>
                    <div class="mb-3 form-check">
                        <input type="checkbox" name="loop_execution" class="form-check-input" id="loop_execution" {% if strat.loop_execution %}checked{% endif %}>
                        <label class="form-check-label" for="loop_execution">是否循环执行</label>
                    </div>
                    <div class="mb-3 form-check">
                        <input type="checkbox" name="use_order_timeout" id="use_order_timeout" class="form-check-input" {% if strat.order_timeout > 0 %}checked{% endif %}>
                        <label class="form-check-label" for="use_order_timeout">启用下单超时</label>
                    </div>
                    <div id="order_timeout_input" style="display: {% if strat.order_timeout > 0 %}block{% else %}none{% endif %};">
                        <div class="mb-3">
                            <label class="form-label">下单超时（秒）</label>
                            <input type="number" name="order_timeout" class="form-control" value="{{ strat.order_timeout or 60 }}" step="1" required>
                        </div>
                    </div>
                    <button type="submit" class="btn btn-primary">保存并重启</button>
                    <a href="{{ url_for('index') }}" class="btn btn-secondary">返回</a>
                </form>
            </div>
        </div>
    </div>
</body>
</html>
"""

api_settings_html = """
<!DOCTYPE html>
<html>
<head>
    <title>API 配置</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <div class="container mt-4">
        <h3>API 配置</h3>
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                {% for message in messages %}
                    <div class="alert alert-info">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <div class="card mb-3">
            <div class="card-body">
                <form method="post">
                    <div class="mb-3">
                        <label class="form-label">API 名称</label>
                        <input type="text" name="name" class="form-control" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">交易所</label>
                        <select name="exchange" class="form-select" required>
                            <option value="okx">OKX</option>
                        </select>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">API Key</label>
                        <input type="text" name="api_key" class="form-control" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">API Secret</label>
                        <input type="text" name="api_secret" class="form-control" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">交易密码（Passphrase）</label>
                        <input type="text" name="password" class="form-control">
                    </div>
                    <div class="mb-3 form-check">
                        <input type="checkbox" name="is_test_mode" class="form-check-input" id="is_test_mode" checked>
                        <label class="form-check-label" for="is_test_mode">模拟账户</label>
                    </div>
                    <div class="mt-3">
                        <button type="submit" name="test_connection" class="btn btn-warning">测试链接</button>
                        <button type="submit" class="btn btn-primary">添加 API</button>
                    </div>
                </form>
            </div>
        </div>
        <div class="card">
            <div class="card-header">已添加的 API</div>
            <div class="card-body">
                {% if api_configs %}
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>名称</th><th>交易所</th><th>API Key</th><th>类型</th><th>操作</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for api in api_configs %}
                                <tr>
                                    <td>{{ api['name'] }}</td>
                                    <td>{{ api['exchange'] }}</td>
                                    <td>{{ api['api_key'][:4] }}...</td>
                                    <td>{{ '模拟账户' if api.get('is_test_mode', True) else '实盘账户' }}</td>
                                    <td>
                                        <a href="{{ url_for('delete_api', api_id=api['exchange'] + '_' + api['api_key']) }}" class="btn btn-danger btn-sm">删除</a>
                                    </td>
                                </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                {% else %}
                    <p class="text-muted">暂无 API 配置</p>
                {% endif %}
                <a href="{{ url_for('index') }}" class="btn btn-secondary mt-3">返回</a>
            </div>
        </div>
    </div>
</body>
</html>
"""

trades_html = """
<!DOCTYPE html>
<html>
<head>
    <title>交易记录</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .pagination {
            margin-top: 20px;
            justify-content: center;
        }
    </style>
</head>
<body class="bg-light">
    <div class="container mt-4">
        <h3>交易记录</h3>
        <div class="card mb-3">
            <div class="card-body">
                <form method="get" class="row g-3">
                    <div class="col-md-4">
                        <label class="form-label">开始日期</label>
                        <input type="date" name="start_date" class="form-control" value="{{ start_date }}">
                    </div>
                    <div class="col-md-4">
                        <label class="form-label">结束日期</label>
                        <input type="date" name="end_date" class="form-control" value="{{ end_date }}">
                    </div>
                    <div class="col-md-2">
                        <label class="form-label">每页显示</label>
                        <select name="per_page" class="form-select" onchange="this.form.submit()">
                            <option value="20" {% if per_page == 20 %}selected{% endif %}>20</option>
                            <option value="50" {% if per_page == 50 %}selected{% endif %}>50</option>
                            <option value="100" {% if per_page == 100 %}selected{% endif %}>100</option>
                        </select>
                    </div>
                    <div class="col-md-2 d-flex align-items-end">
                        <button type="submit" class="btn btn-primary">查询</button>
                    </div>
                </form>
            </div>
        </div>
        <div class="card">
            <div class="card-body">
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>ID</th><th>交易对</th><th>动作</th><th>价格</th><th>金额</th>
                            <th>时间</th><th>盈利</th><th>盈利%</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for trade in trades %}
                            <tr>
                                <td>{{ trade[0] }}</td>
                                <td>{{ trade[1] }}</td>
                                <td>{{ trade[2] }}</td>
                                <td>{{ trade[3]|round(6) }}</td>
                                <td>{{ trade[4]|round(2) }}</td>
                                <td>{{ trade[5] }}</td>
                                <td>{{ trade[6]|round(2) if trade[6] is not none else '-' }}</td>
                                <td>{{ trade[7]|round(2) if trade[7] is not none else '-' }}%</td>
                            </tr>
                        {% endfor %}
                    </tbody>
                </table>
                <nav aria-label="Page navigation">
                    <ul class="pagination">
                        {% if page > 1 %}
                            <li class="page-item">
                                <a class="page-link" href="{{ url_for('trades', page=page-1, per_page=per_page, start_date=start_date, end_date=end_date) }}">上一页</a>
                            </li>
                        {% endif %}
                        {% for p in range(1, total_pages + 1) %}
                            <li class="page-item {% if p == page %}active{% endif %}">
                                <a class="page-link" href="{{ url_for('trades', page=p, per_page=per_page, start_date=start_date, end_date=end_date) }}">{{ p }}</a>
                            </li>
                        {% endfor %}
                        {% if page < total_pages %}
                            <li class="page-item">
                                <a class="page-link" href="{{ url_for('trades', page=page+1, per_page=per_page, start_date=start_date, end_date=end_date) }}">下一页</a>
                            </li>
                        {% endif %}
                    </ul>
                </nav>
                <a href="{{ url_for('index') }}" class="btn btn-secondary mt-3">返回</a>
            </div>
        </div>
    </div>
</body>
</html>
"""

profits_html = """
<!DOCTYPE html>
<html>
<head>
    <title>利润统计</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <div class="container mt-4">
        <h3>每日利润统计</h3>
        <div class="card mb-3">
            <div class="card-body">
                <form method="get" class="row g-3">
                    <div class="col-md-4">
                        <label class="form-label">开始日期</label>
                        <input type="date" name="start_date" class="form-control" value="{{ start_date }}">
                    </div>
                    <div class="col-md-4">
                        <label class="form-label">结束日期</label>
                        <input type="date" name="end_date" class="form-control" value="{{ end_date }}">
                    </div>
                    <div class="col-md-4 d-flex align-items-end">
                        <button type="submit" class="btn btn-primary">查询</button>
                    </div>
                </form>
            </div>
        </div>
        <div class="card">
            <div class="card-body">
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>结算币 (USDT)</th><th>日期</th><th>利润</th><th>出单数</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% if daily_profits %}
                            {% for profit in daily_profits %}
                                <tr>
                                    <td>{{ profit[0] }}</td>
                                    <td>{{ profit[1] }}</td>
                                    <td>{{ profit[2]|round(2) if profit[2] is not none else '0.00' }}</td>
                                    <td>{{ profit[3] }}</td>
                                </tr>
                            {% endfor %}
                        {% else %}
                            <tr>
                                <td colspan="4" class="text-center">暂无数据</td>
                            </tr>
                        {% endif %}
                    </tbody>
                </table>
                <a href="{{ url_for('index') }}" class="btn btn-secondary">返回</a>
            </div>
        </div>
    </div>
</body>
</html>
"""

assets_html = """
<!DOCTYPE html>
<html>
<head>
    <title>资产查询</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <div class="container mt-4">
        <h3>资产查询</h3>
        <div class="card mb-3">
            <div class="card-body">
                <form method="post" class="row g-3">
                    <div class="col-md-6">
                        <label class="form-label">选择 API</label>
                        <select name="api_id" class="form-select" required>
                            <option value="">请选择 API</option>
                            {% for api in api_configs %}
                                <option value="{{ api['exchange'] }}_{{ api['api_key'] }}" {% if selected_api == api['exchange'] + '_' + api['api_key'] %}selected{% endif %}>
                                    {{ api['name'] }} ({{ api['exchange'] }} - {{ api['api_key'][:4] }}...)
                                </option>
                            {% endfor %}
                        </select>
                    </div>
                    <div class="col-md-6 d-flex align-items-end">
                        <button type="submit" class="btn btn-primary">查询</button>
                    </div>
                </form>
            </div>
        </div>
        <div class="card">
            <div class="card-body">
                {% if assets %}
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>币种</th><th>可用余额</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for currency, balance in assets.items() %}
                                <tr>
                                    <td>{{ currency }}</td>
                                    <td>{{ balance|round(8) }}</td>
                                </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                {% else %}
                    <p class="text-muted">请选择 API 并查询资产</p>
                {% endif %}
                <a href="{{ url_for('index') }}" class="btn btn-secondary">返回</a>
            </div>
        </div>
    </div>
</body>
</html>
"""

confirm_delete_html = """
<!DOCTYPE html>
<html>
<head>
    <title>确认删除策略</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <div class="container mt-4">
        <h3>确认删除策略 - {{ strat.symbol }}</h3>
        <div class="card">
            <div class="card-body">
                <p>您即将删除策略 {{ strat.symbol }}。请选择是否保留当前持仓：</p>
                <form method="post">
                    <div class="mb-3">
                        <label class="form-label">保留当前交易</label>
                        <select name="retain_positions" class="form-select">
                            <option value="yes">是（仅删除策略，保留持仓）</option>
                            <option value="no">否（卖出持仓并删除策略）</option>
                        </select>
                    </div>
                    <button type="submit" class="btn btn-danger">确认删除</button>
                    <a href="{{ url_for('index') }}" class="btn btn-secondary">取消</a>
                </form>
            </div>
        </div>
    </div>
</body>
</html>
"""

confirm_delete_api_html = """
<!DOCTYPE html>
<html>
<head>
    <title>确认删除 API 配置</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <div class="container mt-4">
        <h3>确认删除 API 配置 - {{ api.name }}</h3>
        <div class="card">
            <div class="card-body">
                <p>您即将删除 API 配置 {{ api.name }} ({{ api.exchange }} - {{ api.api_key[:4] }}...)。此操作不可撤销。</p>
                <form method="post">
                    <button type="submit" class="btn btn-danger">确认删除</button>
                    <a href="{{ url_for('api_settings') }}" class="btn btn-secondary">取消</a>
                </form>
            </div>
        </div>
    </div>
</body>
</html>
"""

# 保存模板
import os
if not os.path.exists('templates'):
    os.makedirs('templates')
with open('templates/login.html', 'w') as f:
    f.write(login_html)
with open('templates/index.html', 'w') as f:
    f.write(index_html)
with open('templates/settings.html', 'w') as f:
    f.write(settings_html)
with open('templates/edit_strategy.html', 'w') as f:
    f.write(edit_strategy_html)
with open('templates/api_settings.html', 'w') as f:
    f.write(api_settings_html)
with open('templates/trades.html', 'w') as f:
    f.write(trades_html)
with open('templates/profits.html', 'w') as f:
    f.write(profits_html)
with open('templates/assets.html', 'w') as f:
    f.write(assets_html)
with open('templates/confirm_delete.html', 'w') as f:
    f.write(confirm_delete_html)
with open('templates/confirm_delete_api.html', 'w') as f:
    f.write(confirm_delete_api_html)

if __name__ == "__main__":
    init_db()
    app.run(debug=False, host='0.0.0.0', port=5000)