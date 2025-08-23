from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class UserAsymmetricKey(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='asymmetric_key')
    public_key = models.TextField()
    private_key = models.BinaryField() # Encrypted private key

    def __str__(self):
        return f"Asymmetric key for {self.user.username}"

class SharedKey(models.Model):
    user1 = models.ForeignKey(User, on_delete=models.CASCADE, related_name='shared_keys1')
    user2 = models.ForeignKey(User, on_delete=models.CASCADE, related_name='shared_keys2')
    key = models.TextField()

    class Meta:
        unique_together = ('user1', 'user2')

    def __str__(self):
        return f"Shared key between {self.user1.username} and {self.user2.username}"
