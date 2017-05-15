<?php
use symo\JWTAuth\examples\User;
use symo\JWTAuth\JWTAuth;

require(__DIR__."/../vendor/autoload.php");

$user = new User();

$token = (new JWTAuth())->fromUser($user);
print_r((string)$token);