"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.http import HttpResponse

def home(request):
    return HttpResponse("Welcome to my Django app!")


urlpatterns = [
    path('', home),
    path('admin/', admin.site.urls),
    path('api/records/', include('posts.urls')),
    path('api-auth/', include('rest_framework.urls')),
    path('api/', include('dj_rest_auth.urls')),
    path('api/reg', include('dj_rest_auth.registration.urls')),
    path('api/google-login', include('posts.urls')),
    path('api/google-signup', include('posts.urls')),
   
]
