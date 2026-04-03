from decouple import config

firebase_config = {
    'apiKey': config('FIREBASE_API_KEY'),
    'authDomain': config('FIREBASE_AUTH_DOMAIN'),
    'databaseURL': config('FIREBASE_DATABASE_URL'),
    'projectId': config('FIREBASE_PROJECT_ID'),
    'storageBucket': config('FIREBASE_STORAGE_BUCKET'),
    'messagingSenderId': config('FIREBASE_MESSAGING_SENDER_ID'),
    'appId': config('FIREBASE_APP_ID'),
    'measurementId': config('FIREBASE_MEASUREMENT_ID'),
    'serviceAccount': config('FIREBASE_SERVICE_ACCOUNT_DEV') if config('PYTHON_ENV') == 'dev' else config('FIREBASE_SERVICE_ACCOUNT_PROD'),
}
