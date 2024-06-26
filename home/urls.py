from django.urls import path
from channels.routing import ProtocolTypeRouter, URLRouter
from . import views, consumers

urlpatterns = [
    path('', views.index, name="index"),
    path('register/', views.u_register, name='register'),
    path('login/', views.u_login, name="login"),
    path('files/', views.list_uploaded_files, name='list_uploaded_files'),
    path('file_statistics', views.file_statistics, name='file_statistics'),
    path('files/<int:file_id>/edit/', views.edit_report, name='edit_report'),
    path('files/<int:file_id>/', views.view_report, name='view_report'),
    path('submit_report/<str:language_name>/<str:signatures>/', views.submit_report, name='submit_report'),
    path('submit_report/<str:language_name>/', views.submit_report, name='submit_report_no_signatures'),
    path('analyse/<str:language_name>/<str:signatures>/', views.analyse, name='analyse'),
    path('analyse/<str:language_name>/', views.analyse, name='analyse_no_signatures'),
    # other paths...
    path('validate_root_password/', views.validate_root_password, name='validate_root_password'),
    path('image_steg', views.image_steg, name='image_steg'),
    path('network_capture/', views.network_capture, name='network_capture'),
    path('select_interface', views.select_interface, name='select_interface'),
    path('upload', views.upload_file, name='upload_file'),
    # path('report', views.submit_report, name='submit_report'),
]


websocket_urlpatterns = [
    path('ws/notifications/', consumers.NotificationConsumer.as_asgi()),
]

application = ProtocolTypeRouter({
    'websocket': URLRouter(websocket_urlpatterns),
})
