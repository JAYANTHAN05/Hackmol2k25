from django.urls import path
from . import views

urlpatterns = [
    path('api/ssl-check/', views.SSLCheckView.as_view(), name='ssl-check'),
]