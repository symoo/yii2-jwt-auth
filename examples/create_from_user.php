<?php
use symo\JWT\User;
use symo\JWTAuth\JWTAuth;

require(__DIR__."/../vendor/autoload.php");
require(__DIR__ . '/../vendor/yiisoft/yii2/Yii.php');

new yii\web\Application([
    'id' => 'api',
    'basePath' => basename(__DIR__),
    'components' => [
        'jwt' => [
            'class' => JWTAuth::class,
        ],
    ]
]); // Do NOT call run() here

$user = new User();
$user->id = 1;
$token = Yii::$app->jwt->fromUser($user);
echo (string)$token . PHP_EOL;

/** @var JWTAuth $result */
$result = Yii::$app->jwt;
$result->parse($token)->validate();
print_r($result);

