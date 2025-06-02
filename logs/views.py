from django.shortcuts import render
from django.http import JsonResponse
from django.views import View
from .models import LogEntry
from .analyzers import AnomalyDetector
import json

from .parsers import ParserFactory


class LogIngestView(View):
    def post(self, request):
        try:
            data = json.loads(request.body)
            parser = ParserFactory.get_parser(data.get('log_type'))
            if not parser:
                return JsonResponse({'error': 'Unsupported log type'}, status=400)

            parsed_data = parser.parse(data['log_line'])
            if parsed_data:
                LogEntry.objects.create(**parsed_data)
                return JsonResponse({'status': 'success'})
            return JsonResponse({'error': 'Parse failed'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)


class AnomalyDashboard(View):
    def get(self, request):
        detector = AnomalyDetector()

        context = {
            'brute_force': detector.detect_brute_force(),
            'unusual_logins': detector.detect_time_based_anomalies('login'),
            'recent_logs': LogEntry.objects.order_by('-timestamp')[:50]
        }

        return render(request, 'logs/dashboard.html', context)