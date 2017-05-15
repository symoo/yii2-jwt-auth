<?php

namespace symo\JWTAuth;

class Token extends \Lcobucci\JWT\Token
{
    public function getSub()
    {
        return $this->getClaim('sub');
    }
}