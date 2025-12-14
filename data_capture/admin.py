from django.contrib import admin
from .models import DataSource, ExtractedData, ContactMessage, AuditLog


@admin.register(DataSource)
class DataSourceAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'user',
        'source_type',
        'file_name',
        'created_at',
        'short_file_hash',
    )
    list_filter = ('source_type', 'created_at', 'user')
    search_fields = ('file_name', 'user__username', 'file_hash')
    readonly_fields = ('file_hash', 'created_at', 'updated_at')

    fieldsets = (
        (None, {
            'fields': ('user', 'source_type', 'file_name')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
        }),
        ('Security / Integrity', {
            'fields': ('file_hash',),
        }),
    )

    def short_file_hash(self, obj):
        if obj.file_hash:
            return obj.file_hash[:10] + "..."
        return "-"
    short_file_hash.short_description = "File Hash"


@admin.register(ExtractedData)
class ExtractedDataAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'source',
        'user',
        'created_at',
        'short_content_hash',
    )
    list_filter = ('created_at', 'user')
    search_fields = ('data', 'content_hash', 'source__file_name', 'user__username')
    readonly_fields = ('content_hash', 'created_at')

    fieldsets = (
        (None, {
            'fields': ('source', 'user')
        }),
        ('Content', {
            'fields': ('data',),
        }),
        ('Security / Integrity', {
            'fields': ('content_hash',),
        }),
        ('Timestamps', {
            'fields': ('created_at',),
        }),
    )

    def short_content_hash(self, obj):
        if obj.content_hash:
            return obj.content_hash[:10] + "..."
        return "-"
    short_content_hash.short_description = "Content Hash"


@admin.register(ContactMessage)
class ContactMessageAdmin(admin.ModelAdmin):
    list_display = ('id', 'subject', 'name', 'email', 'created_at', 'is_resolved')
    list_filter = ('is_resolved', 'created_at')
    search_fields = ('subject', 'name', 'email', 'message')
    readonly_fields = ('name', 'email', 'subject', 'message', 'created_at', 'user')

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('created_at', 'user', 'action', 'ip_address')
    list_filter = ('action', 'created_at', 'user')
    search_fields = ('message', 'user__username', 'ip_address', 'user_agent')
    readonly_fields = ('created_at', 'user', 'action', 'message', 'ip_address', 'user_agent')
