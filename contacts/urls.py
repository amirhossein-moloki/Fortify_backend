from django.urls import path
from . import views

urlpatterns = [
    path('', views.ContactListView.as_view(), name='contact-list'),
    path('add/', views.ContactCreateView.as_view(), name='contact-add'),
    path('<int:pk>/delete/', views.ContactDeleteView.as_view(), name='contact-delete'),
    path('friend-request/<int:pk>/<str:action>/', views.FriendRequestActionView.as_view(), name='friend-request-action'),
    path('block/<str:username>/', views.BlockUserView.as_view(), name='block-user'),
]
