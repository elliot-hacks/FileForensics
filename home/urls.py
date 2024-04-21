from django.urls import path
from channels.routing import ProtocolTypeRouter, URLRouter
from . import views, consumers

urlpatterns = [
    path('', views.index, name="index"),
    path('register', views.u_register, name="register"),
    path('login', views.u_login, name="login"),
    # path('malware', views.malware, name="malware"),
    path('analyse/<str:language_name>/<str:signatures>/', views.analyse, name='analyse'),  # Define the URL pattern for analyzing files
    path('validate_root_password/', views.validate_root_password, name='validate_root_password'),
    path('image_steg', views.image_steg, name='image_steg'),
    path('network_capture/', views.network_capture, name='network_capture'),
    path('select_interface', views.select_interface, name='select_interface'),
    path('upload', views.upload_file, name='upload_file'),
    path('report', views.submit_report, name='submit_report'),
]


websocket_urlpatterns = [
    path('ws/notifications/', consumers.NotificationConsumer.as_asgi()),
]

application = ProtocolTypeRouter({
    'websocket': URLRouter(websocket_urlpatterns),
})
