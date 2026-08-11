phishing-detector/
├── data/                       # Training dataset
├── model/
│   ├── explore.py              # Dataset exploration
│   └── train.py                # Model training script
├── backend/
│   ├── main.py                 # FastAPI app & /predict endpoint
│   ├── feature_extractor.py    # Live URL feature extraction (30 signals)
│   ├── phishing_model.pkl      # Trained model (not tracked in git)
│   ├── feature_columns.pkl     # Feature column order (not tracked in git)
│   ├── requirements.txt        # Python dependencies
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── App.jsx             # Main UI component
│   │   └── App.css             # Styling
│   └── Dockerfile
└── docker-compose.yml          # Runs backend + frontend together
