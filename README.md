# Scam Radar
### What Do Malicious Links Look Like, and Who Do They Impersonate?

Scam Radar is a malicious URL detection and analysis project. It collects reported malicious URLs from threat intelligence sources, processes and validates the data, stores records in a database, and provides a dashboard and URL checker.

## Project Objectives

- Collect real-world reported malicious URLs.
- Identify suspicious URL patterns and characteristics.
- Analyze threats, domains, TLDs, and impersonated brands.
- Store validated URL records in a database.
- Provide a dashboard for threat intelligence visualization.
- Allow users to check URLs using database records and local pattern analysis.

## Data Sources

### 1. URLhaus
URLhaus by abuse.ch provides reported URLs associated with malware distribution.

### 2. OpenPhish
OpenPhish provides phishing intelligence used as an additional source for URL checking and analysis.

## Technologies Used

### Backend and Data Processing
- Python
- FastAPI
- Requests
- Pandas
- Pydantic
- SQLAlchemy
- SQLite
- APScheduler

### Frontend
- Next.js
- React
- TypeScript
- Tailwind CSS
- Recharts
- Lucide Icons

## Project Architecture

The project follows an ETL (Extract, Transform, Load) pipeline.

1. **Extract:** Collect URL intelligence from external sources.
2. **Transform:** Clean, normalize, and process the collected records.
3. **Validate:** Validate records and separate invalid data.
4. **Feature Engineering:** Extract URL features such as domain, TLD, path length, and suspicious keywords.
5. **Load:** Store processed records in the database and export datasets.
6. **Analyze:** Generate threat statistics and URL pattern reports.
7. **Visualize:** Display results through the web dashboard.

## Main Features

- Automated URL intelligence collection.
- URL validation and duplicate removal.
- Domain and TLD analysis.
- Suspicious URL pattern detection.
- Local heuristic risk scoring.
- Database-based malicious URL lookup.
- OpenPhish checking.
- Interactive threat intelligence dashboard.
- Scheduled data collection.

## URL Checker

The URL checker uses three analysis methods:

1. **Database Analysis:** Checks whether a URL exists in the collected malicious URL database.
2. **Local Analysis:** Examines URL structure and suspicious patterns to calculate a heuristic risk score.
3. **OpenPhish Analysis:** Checks phishing intelligence through OpenPhish.

The local risk score is a heuristic indicator. It does not prove that a URL is malicious or guarantee that an unflagged URL is safe.

## Backend Setup

Activate the virtual environment:

```powershell
.\venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

Configure the required environment variables in your local `.env` file. Never publish API keys or secrets.

Start the backend:

```powershell
python -m uvicorn src.api:app --reload
```

Backend address:

```text
http://127.0.0.1:8000
```

## Frontend Setup

Open a separate terminal:

```powershell
cd frontend-app
npm install
npm run dev
```

Frontend address:

```text
http://localhost:3000
```

## API Endpoints

| Endpoint | Purpose |
|---|---|
| `/` | Home endpoint |
| `/health` | Backend health check |
| `/dashboard` | Dashboard statistics |
| `/check` | URL checking |

## Running Tests

Run the complete test suite:

```powershell
python -m unittest discover -s tests -v
```

## Project Structure

```text
Scam-Radar/
│
├── src/
│   ├── apis/
│   ├── etl/
│   ├── checker/
│   ├── database/
│   └── api.py
│
├── frontend-app/
│
├── tests/
│
├── data/
│   ├── processed/
│   └── rejected/
│
├── .env
├── requirements.txt
└── README.md
```

## Security Note

Scam Radar is an educational threat intelligence and URL analysis project. Do not open suspicious URLs directly. A URL not found in the database or receiving a low heuristic score should not automatically be considered safe.

## Project Status

The backend, frontend dashboard, database integration, URL checker, and automated tests have been implemented and tested.

The project is designed to support future improvements in malicious URL analysis and threat intelligence.