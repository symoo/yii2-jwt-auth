<?php

namespace symo\JWTAuth\Exceptions;

use Throwable;
use yii\base\UserException;

class JWTException extends UserException
{
    public function __construct($message = "Something goes wrong", $code = 0, Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}