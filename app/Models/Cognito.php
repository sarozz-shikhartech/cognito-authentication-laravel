<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Cognito extends Model
{
    use HasFactory;

    protected $table = 'cognito';

    protected $fillable = [
        'store_id', 'user_id', 'client_name', 'pool_name', 'client_id', 'pool_id'
    ];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class, 'id', 'user_id');
    }
}
