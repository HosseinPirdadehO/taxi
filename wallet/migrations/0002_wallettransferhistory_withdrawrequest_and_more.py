# Generated by Django 5.2.4 on 2025-07-22 13:23

import django.db.models.deletion
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('wallet', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='WalletTransferHistory',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('amount', models.DecimalField(decimal_places=2, max_digits=12)),
                ('status', models.CharField(choices=[('pending', 'در انتظار'), ('completed', 'کامل شده'), ('failed', 'ناموفق'), ('reversed', 'برگشت خورده')], default='pending', max_length=20)),
                ('reference_code', models.CharField(blank=True, max_length=100, null=True, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('from_wallet', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='outgoing_transfers', to='wallet.wallet')),
                ('to_wallet', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='incoming_transfers', to='wallet.wallet')),
            ],
        ),
        migrations.CreateModel(
            name='WithdrawRequest',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('amount', models.DecimalField(decimal_places=2, max_digits=12)),
                ('status', models.CharField(choices=[('pending', 'در انتظار'), ('approved', 'تایید شده'), ('rejected', 'رد شده')], default='pending', max_length=10)),
                ('requested_at', models.DateTimeField(auto_now_add=True)),
                ('processed_at', models.DateTimeField(blank=True, null=True)),
                ('admin_note', models.TextField(blank=True)),
                ('wallet', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='withdraw_requests', to='wallet.wallet')),
            ],
        ),
        migrations.DeleteModel(
            name='WalletErrorLog',
        ),
    ]
