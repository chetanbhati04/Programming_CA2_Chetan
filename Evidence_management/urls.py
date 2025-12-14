"""
URL configuration for scrap_project project.
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import RedirectView

urlpatterns = [
    path('', RedirectView.as_view(pattern_name='home', permanent=False)),
    path('admin/', admin.site.urls),
    path('api/auth/', include('authentication.urls')),
    path('api/data/', include('data_capture.urls')),
    path('', include('authentication.urls')),
    path('', include('data_capture.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

