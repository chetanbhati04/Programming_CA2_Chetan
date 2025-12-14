# data_capture/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('home/', views.home, name='home'),
    path('upload/', views.upload_file, name='upload_file'),
    path('api/upload/', views.api_upload_file, name='api_upload_file'),
    path('source/<int:pk>/', views.source_detail, name='source_detail'),
    path('contact/', views.contact, name='contact'),
    path('source/<int:pk>/delete/', views.delete_source, name='delete_source'),
]
