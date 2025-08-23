from rest_framework import serializers
from .models import Chat, Message, Attachment, Role, Reaction
from accounts.serializers import UserSerializer
from .models import Chat, Message
from rest_framework import serializers

class ReactionSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = Reaction
        fields = ('id', 'user', 'emoji', 'created_at')

class PinnedMessageSerializer(serializers.ModelSerializer):
    sender = UserSerializer(read_only=True)
    reactions = ReactionSerializer(many=True, read_only=True)

    class Meta:
        model = Message
        fields = ('id', 'sender', 'content', 'timestamp', 'is_edited', 'is_deleted', 'reactions')


# سریالایزر برای مدل Chat
class ChatSerializer(serializers.ModelSerializer):
    participants = UserSerializer(many=True)  # نمایش شرکت‌کنندگان
    group_admin = UserSerializer(many=True)  # تغییر به چند ادمین
    created_at = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S")
    updated_at = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S")
    pinned_message = PinnedMessageSerializer(read_only=True)

    group_name = serializers.SerializerMethodField()
    group_image = serializers.SerializerMethodField()

    class Meta:
        model = Chat
        fields = (
            'id',
            'participants',
            'created_at',
            'updated_at',
            'chat_type',
            'group_name',
            'group_admin',  # تغییر به لیست از ادمین‌ها
            'group_image',
            'max_participants',
            'description',
            'pinned_message',
        )

    def get_group_name(self, obj):
        user = self.context['request'].user
        if obj.chat_type == 'direct':
            other_user = obj.participants.exclude(id=user.id).first()
            return other_user.username if other_user else "Unknown User"
        return obj.group_name if obj.group_name else f"Group {obj.id}"

    def get_group_image(self, obj):
        user = self.context['request'].user
        if obj.chat_type == 'direct':
            other_user = obj.participants.exclude(id=user.id).first()
            return other_user.profile_picture.url if other_user and other_user.profile_picture else None
        return obj.group_image.url if obj.group_image else None


# سریالایزر برای مدل Message
class RecursiveField(serializers.Serializer):
    def to_representation(self, value):
        serializer = self.parent.parent.__class__(value, context=self.context)
        return serializer.data

class MessageSerializer(serializers.ModelSerializer):
    sender = UserSerializer()  # نمایش فرستنده پیام
    chat = ChatSerializer()  # نمایش چت مربوطه
    timestamp = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S")
    read_by = UserSerializer(many=True)  # نمایش کاربرانی که پیام را خوانده‌اند
    reply_to = RecursiveField(read_only=True)
    reactions = ReactionSerializer(many=True, read_only=True)

    class Meta:
        model = Message
        fields = ('id', 'chat', 'sender', 'content', 'timestamp', 'is_read', 'read_by', 'is_edited', 'is_deleted', 'reply_to', 'reactions')

# سریالایزر برای مدل Attachment
class AttachmentSerializer(serializers.ModelSerializer):
    message = MessageSerializer()  # نمایش پیام مربوطه
    url = serializers.HyperlinkedIdentityField(view_name='download_attachment', lookup_field='id', read_only=True)

    class Meta:
        model = Attachment
        fields = ('id', 'message', 'file', 'file_name', 'file_type', 'file_size', 'url')

# سریالایزر برای مدل Role
class RoleSerializer(serializers.ModelSerializer):
    user = UserSerializer()  # نمایش کاربر
    chat = ChatSerializer()  # نمایش چت مربوطه

    class Meta:
        model = Role
        fields = ('id', 'user', 'chat', 'role')


class GetChatsSerializer(serializers.ModelSerializer):
    unread_count = serializers.IntegerField()
    last_message_content = serializers.CharField(source='last_message.content', read_only=True, default=None)
    other_user = serializers.SerializerMethodField()

    # نام گروه یا نام کاربر در چت‌های مستقیم
    group_name = serializers.SerializerMethodField()

    # تصویر گروه یا تصویر پروفایل در چت‌های مستقیم
    group_image = serializers.SerializerMethodField()

    # اطلاعات ادمین‌ها
    group_admin = serializers.SerializerMethodField()

    class Meta:
        model = Chat
        fields = ['id', 'chat_type', 'group_name', 'group_image', 'unread_count', 'other_user', 'last_message_content', 'group_admin']

    def get_other_user(self, obj):
        user = self.context['request'].user
        if obj.chat_type == 'direct':
            # دریافت کاربر مقابل در چت مستقیم
            other_user = obj.participants.exclude(id=user.id).first()
            if other_user:
                return {
                    'id': other_user.id,
                    'username': other_user.username,
                    'profile_picture': other_user.profile_picture.url if other_user.profile_picture else None
                }
        return None

    def get_group_name(self, obj):
        # تعیین نام چت بر اساس نوع آن (گروه یا مستقیم)
        if obj.chat_type == 'direct':
            # برای چت‌های مستقیم، نام کاربر مقابل را نمایش می‌دهیم
            other_user = obj.participants.exclude(id=self.context['request'].user.id).first()
            return other_user.username if other_user else "Unknown User"
        # برای چت‌های گروهی، نام گروه نمایش داده می‌شود
        return obj.group_name if obj.group_name else f"Group {obj.id}"

    def get_group_image(self, obj):
        # تعیین تصویر چت بر اساس نوع آن (گروه یا مستقیم)
        if obj.chat_type == 'direct':
            # برای چت‌های مستقیم، تصویر پروفایل کاربر مقابل را نمایش می‌دهیم
            other_user = obj.participants.exclude(id=self.context['request'].user.id).first()
            return other_user.profile_picture.url if other_user and other_user.profile_picture else None
        # برای چت‌های گروهی، تصویر گروه نمایش داده می‌شود
        return obj.group_image.url if obj.group_image else None

    def get_group_admin(self, obj):
        # نمایش ادمین‌های گروه
        return UserSerializer(obj.group_admin.all(), many=True).data
