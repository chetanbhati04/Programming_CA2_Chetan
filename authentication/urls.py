from django.urls import path
from . import views

urlpatterns = [
    # API endpoints (under /api/auth/)
    path('api/register/', views.register_api, name='register_api'),
    path('api/login/', views.login_api, name='login_api'),
    path('api/logout/', views.logout_api, name='logout_api'),
    # Web pages (root level)
    path('login/', views.login_page, name='login'),
    path('register/', views.register_page, name='register'),
    # Form handlers (root level)
    path('register-view/', views.register_view, name='register_view'),
    path('login-view/', views.login_view, name='login_view'),
    path('logout/', views.logout_view, name='logout_view'),
]

