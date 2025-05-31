from django.urls import path
from .views import PostListCreateView,PostDetailView
from . import views

urlpatterns = [
    path('', PostListCreateView.as_view(), name='post-list-create'),
    path('api/google-login', views.google_login),
    path('api/google-signup', views.google_signup),
    path('<int:pk>/', PostDetailView.as_view(), name='post-detail'),
]