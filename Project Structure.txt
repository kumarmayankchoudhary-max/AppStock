 Project Structure

  stock-analysis-platform/
  ├── backend/
  │   ├── main.py
  │   ├── security_validator.py
  │   ├── data_ingestor.py
  │   ├── analysis_engine.py
  │   ├── portfolio_manager.py
  │   ├── requirements.txt
  │   └── .env
  └── stock_analysis_flutter/
      ├── pubspec.yaml
      └── lib/
          ├── main.dart
          ├── models/
          │   └── stock_analysis.dart
          ├── services/
          │   └── api_service.dart
          └── screens/
              ├── home_screen.dart
              ├── details_screen.dart
              └── portfolio_screen.dart

  ---

  📂 PART 1: THE BACKEND (Python/FastAPI)

  backend/requirements.txt

  fastapi
  uvicorn
  httpx
  pandas
  ta-lib
  pydantic
  python-dotenv
  beautifulsoup4
  feedparser

  backend/security_validator.py

  import httpx
  import os
  from typing import Dict, Any
  from dotenv import load_dotenv

  load_dotenv()

  class SecurityValidator:
      def __init__(self):
          self.virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")
          self.sucuri_api_key = os.getenv("SUCURI_API_KEY")
          self.observatory_url = "https://observatory.mozilla.org/api/v1/analyze"

      async def check_virustotal(self, url: str) -> Dict[str, Any]:
          if not self.virustotal_api_key: return {"status": "skipped"}
          async with httpx.AsyncClient() as client:
              response = await client.get(f"https://www.virustotal.com/api/v3/urls",
                                         headers={"x-apikey": self.virustotal_api_key}, params={"url": url})
              return response.json() if response.status_code == 200 else {"status": "error"}

      async def check_sucuri(self, url: str) -> Dict[str, Any]:
          if not self.sucuri_api_key: return {"status": "skipped"}
          async with httpx.AsyncClient() as client:
              response = await client.get(f"https://sitecheck.sucuri.net/api/scan",
                                         params={"url": url, "api_key": self.sucuri_api_key})
              return response.json() if response.status_code == 200 else {"status": "error"}

      async def check_mozilla_observatory(self, url: str) -> Dict[str, Any]:
          async with httpx.AsyncClient() as client:
              response = await client.post(self.observatory_url, data={"url": url})
              return response.json() if response.status_code == 200 else {"status": "error"}

      async def validate_source(self, url: str) -> bool:
          vt = await self.check_virustotal(url)
          sucuri = await self.check_sucuri(url)
          if vt.get("status") == "malicious" or sucuri.get("status") == "infected":
              return False
          return True

  backend/data_ingestor.py

  import httpx
  import feedparser
  from bs4 import BeautifulSoup
  from typing import List, Dict, Any
  import os

  class DataIngestor:
      def __init__(self, security_validator):
          self.security_validator = security_validator
          self.financial_api_key = os.getenv("FINANCIAL_API_KEY")

      async def fetch_rss_news(self, rss_url: str) -> List[Dict[str, str]]:
          feed = feedparser.parse(rss_url)
          return [{"title": e.title, "link": e.link, "summary": e.get("summary", "")} for e in feed.entries]

      async def scrape_website(self, url: str) -> str:
          if not await self.security_validator.validate_source(url):
              return "ERROR: Source failed security validation."
          async with httpx.AsyncClient() as client:
              response = await client.get(url)
              if response.status_code == 200:
                  soup = BeautifulSoup(response.text, 'html.parser')
                  return " ".join([p.get_text() for p in soup.find_all('p')])
              return "ERROR: Could not fetch content."

      async def get_stock_data(self, symbol: str) -> Dict[str, Any]:
          if not self.financial_api_key: return {"error": "API Key missing"}
          async with httpx.AsyncClient() as client:
              response = await client.get(f"https://www.alphavantage.co/query",
                                         params={"function": "TIME_SERIES_DAILY", "symbol": symbol, "apikey":
  self.financial_api_key})
              return response.json() if response.status_code == 200 else {}

      async def gather_all_info(self, symbol: str, rss_urls: List[str]) -> Dict[str, Any]:
          data = {"symbol": symbol, "technical_data": await self.get_stock_data(symbol), "news": []}
          for url in rss_urls:
              items = await self.fetch_rss_news(url)
              for item in items:
                  if symbol.lower() in item['title'].lower():
                      content = await self.scrape_website(item['link'])
                      data["news"].append({"title": item['title'], "content": content, "link": item['link']})
          return data

  backend/analysis_engine.py

  import pandas as pd
  import ta
  from typing import Dict, Any, List

  class AnalysisEngine:
      def run_technical_analysis(self, stock_data: Dict[str, Any]) -> Dict[str, Any]:
          try:
              ts = stock_data.get("Time Series (Daily)", {})
              if not ts: return {"signal": "neutral", "score": 0, "rsi": 50}
              df = pd.DataFrame.from_dict(ts, orient='index').astype(float).sort_index()
              df['rsi'] = ta.momentum.rsi(df['4. close'], window=14)
              latest = df.iloc[-1]
              rsi = latest['rsi']
              signal = "buy" if rsi < 30 else "sell" if rsi > 70 else "neutral"
              score = 1 if signal == "buy" else -1 if signal == "sell" else 0
              return {"signal": signal, "score": score, "rsi": rsi}
          except: return {"signal": "neutral", "score": 0, "rsi": 50}

      async def run_sentiment_analysis(self, news_list: List[Dict[str, str]]) -> Dict[str, Any]:
          if not news_list: return {"sentiment": "neutral", "score": 0}
          full_text = " ".join([n['content'] for n in news_list])[:4000].lower()
          pos = ['growth', 'surge', 'profit', 'buy', 'upgrade', 'bullish']
          neg = ['drop', 'crash', 'loss', 'sell', 'downgrade', 'bearish']
          score = sum(0.2 for w in pos if w in full_text) - sum(0.2 for w in neg if w in full_text)
          score = max(min(score, 1), -1)
          sentiment = "bullish" if score > 0.2 else "bearish" if score < -0.2 else "neutral"
          return {"sentiment": sentiment, "score": score}

      def apply_rule_based_logic(self, tech_result: Dict, sent_result: Dict) -> Dict[str, Any]:
          combined_score = (tech_result.get("score", 0) * 0.4) + (sent_result.get("score", 0) * 0.6)
          if combined_score > 0.3:
              recommendation, stop_loss = "BUY", (0.05 if combined_score > 0.6 else 0.08)
          elif combined_score < -0.3:
              recommendation, stop_loss = "SELL", 0.05
          else:
              recommendation, stop_loss = "HOLD", 0.0
          return {"recommendation": recommendation, "combined_score": combined_score, "stop_loss_range": stop_loss, "details":
  {"technical": tech_result, "sentiment": sent_result}}

      async def analyze_stock(self, data: Dict[str, Any]) -> Dict[str, Any]:
          tech = self.run_technical_analysis(data.get("technical_data", {}))
          sent = await self.run_sentiment_analysis(data.get("news", []))
          return self.apply_rule_based_logic(tech, sent)

  backend/portfolio_manager.py

  import sqlite3
  from datetime import datetime

  class PortfolioManager:
      def __init__(self, db_path="portfolio.db"):
          self.db_path = db_path
          self._init_db()

      def _init_db(self):
          with sqlite3.connect(self.db_path) as conn:
              conn.execute("CREATE TABLE IF NOT EXISTS trades (id INTEGER PRIMARY KEY AUTOINCREMENT, symbol TEXT, entry_price REAL,
  exit_price REAL, entry_date TEXT, exit_date TEXT, status TEXT)")
              conn.execute("CREATE TABLE IF NOT EXISTS watchlist (symbol TEXT PRIMARY KEY, last_recommendation TEXT)")

      def add_trade(self, symbol, entry_price):
          with sqlite3.connect(self.db_path) as conn:
              conn.execute("INSERT INTO trades (symbol, entry_price, entry_date, status) VALUES (?, ?, ?, ?)", (symbol, entry_price,
  datetime.now().isoformat(), "OPEN"))

      def get_portfolio(self):
          with sqlite3.connect(self.db_path) as conn:
              conn.row_factory = sqlite3.Row
              return [dict(row) for row in conn.execute("SELECT * FROM trades").fetchall()]

      def update_watchlist(self, symbol, rec):
          with sqlite3.connect(self.db_path) as conn:
              conn.execute("INSERT OR REPLACE INTO watchlist (symbol, last_recommendation) VALUES (?, ?)", (symbol, rec))

      def get_watchlist(self):
          with sqlite3.connect(self.db_path) as conn:
              conn.row_factory = sqlite3.Row
              return [dict(row) for row in conn.execute("SELECT * FROM watchlist").fetchall()]

  backend/main.py

  from fastapi import FastAPI, HTTPException
  from fastapi.middleware.cors import CORSMiddleware
  from security_validator import SecurityValidator
  from data_ingestor import DataIngestor
  from analysis_engine import AnalysisEngine
  from portfolio_manager import PortfolioManager
  import uvicorn

  app = FastAPI()
  app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

  security = SecurityValidator()
  ingestor = DataIngestor(security)
  engine = AnalysisEngine()
  portfolio = PortfolioManager()

  DEFAULT_RSS_FEEDS = ["https://feeds.a.viaf.org/finance"]

  @app.get("/analyze/{symbol}")
  async def analyze(symbol: str):
      data = await ingestor.gather_all_info(symbol, DEFAULT_RSS_FEEDS)
      result = await engine.analyze_stock(data)
      return {"symbol": symbol, "recommendation": result["recommendation"], "confidence_score": result["combined_score"],
  "stop_loss_range": result["stop_loss_range"], "analysis": result["details"], "sources_scanned": len(data["news"])}

  @app.post("/portfolio/add")
  async def add_trade(symbol: str, price: float):
      portfolio.add_trade(symbol, price)
      return {"status": "added"}

  @app.get("/portfolio")
  async def get_portfolio():
      return portfolio.get_portfolio()

  if __name__ == "__main__":
      uvicorn.run(app, host="0.0.0.0", port=8000)

  ---

  📂 PART 2: THE FRONTEND (Flutter)

  stock_analysis_flutter/pubspec.yaml

  name: stock_analysis_flutter
  description: Stock Market AI Prediction App
  version: 1.0.0+1
  environment:
    sdk: '>=3.0.0 <4.0.0'
  dependencies:
    flutter:
      sdk: flutter
    http: ^1.1.0

  stock_analysis_flutter/lib/models/stock_analysis.dart

  class StockAnalysis {
    final String symbol;
    final String recommendation;
    final double confidenceScore;
    final TechnicalData technical;
    final SentimentData sentiment;
    final int sourcesScanned;
    final double stopLossRange;

    StockAnalysis({required this.symbol, required this.recommendation, required this.confidenceScore, required this.technical,
  required this.sentiment, required this.sourcesScanned, required this.stopLossRange});

    factory StockAnalysis.fromJson(Map<String, dynamic> json) {
      return StockAnalysis(
        symbol: json['symbol'],
        recommendation: json['recommendation'],
        confidenceScore: (json['confidence_score'] as num).toDouble(),
        technical: TechnicalData.fromJson(json['analysis']['technical']),
        sentiment: SentimentData.fromJson(json['analysis']['sentiment']),
        sourcesScanned: json['sources_scanned'],
        stopLossRange: (json['stop_loss_range'] as num).toDouble(),
      );
    }
  }

  class TechnicalData {
    final double rsi;
    final String signal;
    TechnicalData({required this.rsi, required this.signal});
    factory TechnicalData.fromJson(Map<String, dynamic> json) => TechnicalData(rsi: (json['rsi'] as num?)?.toDouble() ?? 0.0, signal:
  json['signal'] ?? 'neutral');
  }

  class SentimentData {
    final String sentiment;
    final double score;
    SentimentData({required this.sentiment, required this.score});
    factory SentimentData.fromJson(Map<String, dynamic> json) => SentimentData(sentiment: json['sentiment'] ?? 'neutral', score:
  (json['score'] as num).toDouble());
  }

  stock_analysis_flutter/lib/services/api_service.dart

  import 'dart:convert';
  import 'package:http/http.dart' as http;
  import '../models/stock_analysis.dart';

  class ApiService {
    static const String baseUrl = 'http://localhost:8000';
    Future<StockAnalysis> analyzeStock(String symbol) async {
      final response = await http.get(Uri.parse('$baseUrl/analyze/$symbol'));
      if (response.statusCode == 200) return StockAnalysis.fromJson(json.decode(response.body));
      throw Exception('Failed to analyze stock');
    }
  }

  stock_analysis_flutter/lib/screens/home_screen.dart

  import 'package:flutter/material.dart';
  import '../services/api_service.dart';
  import '../models/stock_analysis.dart';
  import 'details_screen.dart';
  import 'portfolio_screen.dart';

  class HomeScreen extends StatefulWidget {
    const HomeScreen({super.key});
    @override
    State<HomeScreen> createState() => _HomeScreenState();
  }

  class _HomeScreenState extends State<HomeScreen> {
    final TextEditingController _controller = TextEditingController();
    final ApiService _apiService = ApiService();
    StockAnalysis? _result;
    bool _isLoading = false;
    String? _error;

    void _analyze() async {
      final symbol = _controller.text.trim().toUpperCase();
      if (symbol.isEmpty) return;
      setState(() { _isLoading = true; _error = null; _result = null; });
      try {
        _result = await _apiService.analyzeStock(symbol);
      } catch (e) {
        setState(() { _error = e.toString(); });
      } finally {
        setState(() { _isLoading = false; });
      }
    }

    @override
    Widget build(BuildContext context) {
      return Scaffold(
        body: Padding(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            children: [
              SizedBox(height: 60, child: Row(mainAxisAlignment: MainAxisAlignment.end, children: [
                IconButton(icon: const Icon(Icons.portfolio, color: Colors.blueAccent),
                onPressed: () => Navigator.push(context, MaterialPageRoute(builder: (context) => const PortfolioScreen())))
              ])),
              const Text('Stock AI Predictor', style: TextStyle(fontSize: 28, fontWeight: FontWeight.bold, color:
  Colors.blueAccent)),
              const SizedBox(height: 40),
              Row(children: [
                Expanded(child: TextField(controller: _controller, decoration: InputDecoration(hintText: 'Symbol', filled: true,
  fillColor: const Color(0xFF1E293B), border: OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide:
  BorderSide.none)))),
                const SizedBox(width: 10),
                ElevatedButton(onPressed: _isLoading ? null : _analyze, child: _isLoading ? const CircularProgressIndicator() : const
  Text('Analyze')),
              ]),
              const SizedBox(height: 30),
              if (_error != null) Text(_error!, style: const TextStyle(color: Colors.red)),
              if (_result != null) ...[
                GestureDetector(
                  onTap: () => Navigator.push(context, MaterialPageRoute(builder: (context) => DetailsScreen(analysis: _result!))),
                  child: Container(
                    width: double.infinity, padding: const EdgeInsets.all(20),
                    decoration: BoxDecoration(color: const Color(0xFF1E293B), borderRadius: BorderRadius.circular(15)),
                    child: Column(children: [
                      Text('Rec for ${_result!.symbol}', style: const TextStyle(color: Colors.grey)),
                      Text(_result!.recommendation, style: TextStyle(fontSize: 48, fontWeight: FontWeight.bold, color:
  _result!.recommendation == 'BUY' ? Colors.greenAccent : Colors.redAccent)),
                      Text('Stop-Loss: ${(_result!.stopLossRange * 100).toStringAsFixed(1)}%', style: const TextStyle(color:
  Colors.redAccent)),
                    ]),
                  ),
                ),
              ],
            ],
          ),
        ),
      );
    }
  }

  stock_analysis_flutter/lib/screens/details_screen.dart

  import 'package:flutter/material.dart';
  import '../models/stock_analysis.dart';

  class DetailsScreen extends StatelessWidget {
    final StockAnalysis analysis;
    const DetailsScreen({super.key, required this.analysis});

    @override
    Widget build(BuildContext context) {
      return Scaffold(
        appBar: AppBar(title: Text('${analysis.symbol} Analysis')),
        body: ListView(
          padding: const EdgeInsets.all(20),
          children: [
            _buildSection('Reasoning', 'Combined confidence score of ${analysis.confidenceScore.toStringAsFixed(2)}'),
            _buildSection('Stop-Loss', 'Limit your loss to ${analysis.stopLossRange * 100}%'),
            _buildSection('Technicals', 'RSI: ${analysis.technical.rsi.toStringAsFixed(2)}'),
            _buildSection('Sentiment', 'Mood: ${analysis.sentiment.sentiment}'),
          ],
        ),
      );
    }

    Widget _buildSection(String title, String content) {
      return Padding(
        padding: const EdgeInsets.only(bottom: 20),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(title, style: const TextStyle(fontSize: 20, fontWeight: FontWeight.bold, color: Colors.blueAccent)),
          Text(content),
        ]),
      );
    }
  }

  stock_analysis_flutter/lib/screens/portfolio_screen.dart

  import 'package:flutter/material.dart';

  class PortfolioScreen extends StatelessWidget {
    const PortfolioScreen({super.key});

    @override
    Widget build(BuildContext context) {
      return Scaffold(
        appBar: AppBar(title: const Text('My Portfolio')),
        body: ListView(
          padding: const EdgeInsets.all(20),
          children: [
            const Text('Active Trades', style: TextStyle(fontSize: 22, fontWeight: FontWeight.bold)),
            const SizedBox(height: 15),
            _buildTradeTile('AAPL', 150.0, 155.0),
            _buildTradeTile('TSLA', 700.0, 680.0),
          ],
        ),
      );
    }

    Widget _buildTradeTile(String symbol, double entry, double current) {
      double pnl = current - entry;
      return Card(
        color: const Color(0xFF1E293B),
        child: ListTile(
          title: Text(symbol),
          subtitle: Text('Entry: \$$entry | Current: \$$current'),
          trailing: Text('${pnl > 0 ? "+" : ""}${pnl.toStringAsFixed(2)}',
            style: TextStyle(color: pnl > 0 ? Colors.greenAccent : Colors.redAccent)),
        ),
      );
    }
  }

  stock_analysis_flutter/lib/main.dart

  import 'package:flutter/material.dart';
  import 'screens/home_screen.dart';

  void main() => runApp(const StockAnalysisApp());

  class StockAnalysisApp extends StatelessWidget {
    const StockAnalysisApp({super.key});
    @override
    Widget build(BuildContext context) {
      return MaterialApp(
        theme: ThemeData(brightness: Brightness.dark, scaffoldBackgroundColor: const Color(0xFF0F172A)),
        home: const HomeScreen(),
      );
    }
  }