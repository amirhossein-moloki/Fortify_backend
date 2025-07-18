from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

# تنظیمات DRF-YASG
schema_view = get_schema_view(
    openapi.Info(
        title="API Documentation",
        default_version='v1',
        description="مستندات API پروژه شما",
        terms_of_service="https://www.example.com/terms/",
        contact=openapi.Contact(email="contact@example.com"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/accounts/', include('accounts.urls')),  # URLهای مربوط به حساب‌ها
    path('api/chats/', include('chats.urls')),  # URLهای مربوط به چت‌ها (برای درخواست‌های API)
    path('api/contacts/', include('contacts.urls')),
    path('api/notifications/', include('notifications.urls')),

    # مستندات Swagger
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),

    # Silk URLs برای پروفایلینگ
    path('silk/', include('silk.urls', namespace='silk')),
]

# افزودن تنظیمات برای فایل‌های مدیا
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
