from rest_framework import serializers
from .models import Post
class PostSerializer(serializers.ModelSerializer):
    author = serializers.SerializerMethodField()

    def get_author(self, obj):
        return obj.author.username if obj.author else None


    class Meta:
        model = Post
        fields = ['id', 'author', 'title', 'body', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']
        