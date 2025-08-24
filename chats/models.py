from django.db import models
from accounts.models import User

class Chat(models.Model):
    CHAT_TYPES = (
        ('direct', 'Direct Chat'),  # چت ساده
        ('group', 'Group Chat'),    # گروه
        ('channel', 'Channel'),     # کانال
    )

    participants = models.ManyToManyField(User, related_name='chats')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    chat_type = models.CharField(max_length=10, choices=CHAT_TYPES, default='direct')
    group_name = models.CharField(max_length=255, null=True, blank=True)  # نام گروه یا کانال
    group_admin = models.ManyToManyField(
        User,
        blank=True,
        related_name='admin_groups'
    )

    max_participants = models.IntegerField(default=50)  # حداکثر تعداد اعضا برای گروه‌ها و کانال‌ها
    description = models.TextField(null=True, blank=True)  # توضیحات چت، گروه یا کانال
    group_image = models.ImageField(upload_to='chat_images/', null=True, blank=True, default='profile_pictures/default_profile_picture.jpg')  # فیلد عکس گروه
    pinned_message = models.ForeignKey('Message', on_delete=models.SET_NULL, null=True, blank=True, related_name='+')

    def add_participant(self, user):
        if self.chat_type != 'direct' and self.participants.count() >= self.max_participants:
            raise ValueError("Maximum number of participants reached.")
        self.participants.add(user)

    def remove_participant(self, user):
        self.participants.remove(user)

    def __str__(self):
        return self.group_name if self.group_name else f"Chat {self.id}"



# مدل Message
class Message(models.Model):
    chat = models.ForeignKey(Chat, on_delete=models.CASCADE, related_name='messages')
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    content = models.BinaryField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    reply_to = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='replies')
    is_read = models.BooleanField(default=False)
    read_by = models.ManyToManyField(User, related_name='read_messages', blank=True)
    delivered_at = models.DateTimeField(null=True, blank=True)
    is_edited = models.BooleanField(default=False)  # پیام ویرایش‌شده
    is_deleted = models.BooleanField(default=False)  # پیام حذف‌شده
    is_forwarded = models.BooleanField(default=False)
    forwarded_from = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='forwarded_messages')
    poll = models.OneToOneField('Poll', on_delete=models.CASCADE, null=True, blank=True)

    def edit_message(self, new_content):
        self.content = new_content
        self.is_edited = True
        self.save()

    def delete_message(self):
        self.content = None
        self.is_deleted = True
        self.save()

    def unread_message_count(self, user):
        """ تعداد پیام‌های خوانده نشده برای کاربر را در چت محاسبه می‌کند """
        unread_messages = self.messages.filter(is_read=False).exclude(read_by=user)
        return unread_messages.count()

    def __str__(self):
        return f"Message {self.id} by {self.sender}"


# مدل Attachment
class Attachment(models.Model):
    ATTACHMENT_TYPES = (
        ('image', 'Image'),
        ('audio', 'Audio'),
        ('file', 'File'),
    )

    message = models.ForeignKey(Message, on_delete=models.CASCADE, related_name='attachments')
    file = models.FileField(upload_to='chat_attachments/')
    file_name = models.CharField(max_length=255)
    file_type = models.CharField(max_length=50)  # مثل image/png, video/mp4
    file_size = models.PositiveIntegerField()  # به بایت
    type = models.CharField(max_length=10, choices=ATTACHMENT_TYPES, default='file')

    def __str__(self):
        return self.file_name


class Reaction(models.Model):
    message = models.ForeignKey(Message, on_delete=models.CASCADE, related_name='reactions')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reactions')
    emoji = models.CharField(max_length=10)  # ذخیره اموجی به صورت کاراکتر
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('message', 'user', 'emoji')

    def __str__(self):
        return f'{self.user.username} reacted with {self.emoji} to message {self.message.id}'


# مدل Role برای مدیریت دسترسی‌ها
class Role(models.Model):
    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('member', 'Member'),
        ('viewer', 'Viewer'),  # فقط برای مشاهده (کانال‌ها)
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    chat = models.ForeignKey(Chat, on_delete=models.CASCADE)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='member')

    def __str__(self):
        return f"{self.user.username} - {self.role} in {self.chat}"


class Poll(models.Model):
    question = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.question

class PollOption(models.Model):
    poll = models.ForeignKey(Poll, on_delete=models.CASCADE, related_name='options')
    text = models.CharField(max_length=255)

    def __str__(self):
        return self.text

class PollVote(models.Model):
    poll_option = models.ForeignKey(PollOption, on_delete=models.CASCADE, related_name='votes')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='votes')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('poll_option', 'user')


class SearchableMessage(models.Model):
    """
    Stores a non-encrypted version of message content for searching purposes.
    This introduces a security trade-off, as message content will be
    accessible on the server.
    """
    message = models.OneToOneField(Message, on_delete=models.CASCADE, related_name='searchable_version')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='searchable_messages')
    content = models.TextField()

    def __str__(self):
        return f"Searchable content for Message {self.message.id} by {self.user.username}"
