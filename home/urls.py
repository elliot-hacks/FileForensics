from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name="index"),
    path('register', views.u_register, name="register"),
    path('login', views.u_login, name="login"),
    # path('malware', views.malware, name="malware"),
    path('analyse', views.analyse, name="analyse"),
    path('upload', views.upload_file, name='upload_file'),
]
