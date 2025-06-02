# logs/analyzers.py
from datetime import datetime, timedelta
from django.db.models import Count
from statsmodels.tsa.seasonal import seasonal_decompose
import pandas as pd
import numpy as np
from .models import LogEntry


class AnomalyDetector:
    def __init__(self):
        self.baseline_period = 30  # days

    def detect_brute_force(self):
        """Detect multiple failed login attempts"""
        window = datetime.now() - timedelta(minutes=15)

        suspicious_logins = (
            LogEntry.objects
            .filter(action='login', status='failed', timestamp__gte=window)
            .values('ip_address', 'user')
            .annotate(failed_attempts=Count('id'))
            .filter(failed_attempts__gte=5)  # Threshold
        )

        return list(suspicious_logins)

    def detect_time_based_anomalies(self, action):
        """Use time series analysis to detect unusual patterns"""
        # Get historical data
        end_date = datetime.now()
        start_date = end_date - timedelta(days=self.baseline_period)

        data = (
            LogEntry.objects
            .filter(action=action, timestamp__range=[start_date, end_date])
            .extra({'date': "date(timestamp)"})
            .values('date')
            .annotate(count=Count('id'))
            .order_by('date')
        )

        if not data:
            return []

        # Convert to pandas DataFrame for analysis
        df = pd.DataFrame(list(data))
        df['date'] = pd.to_datetime(df['date'])
        df.set_index('date', inplace=True)
        df = df.asfreq('D', fill_value=0)

        # Time series decomposition
        result = seasonal_decompose(df['count'], model='additive', period=7)
        residuals = result.resid

        # Detect anomalies (values outside 3 standard deviations)
        threshold = 3 * np.std(residuals)
        anomalies = residuals[abs(residuals) > threshold]

        return anomalies.index.to_list()

    def detect_geographical_anomalies(self, user):
        """Detect logins from unusual locations"""
        user_logins = LogEntry.objects.filter(user=user, action='login')

        if not user_logins.exists():
            return False

        # Get common locations (top 3)
        common_locations = (
            user_logins.values('ip_address')
            .annotate(count=Count('id'))
            .order_by('-count')[:3]
        )
        common_ips = {loc['ip_address'] for loc in common_locations}

        # Check recent login against common locations
        recent_login = user_logins.order_by('-timestamp').first()
        return recent_login.ip_address not in common_ips