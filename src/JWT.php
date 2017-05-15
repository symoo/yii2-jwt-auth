<?php
namespace symo\JWTAuth;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use function time;
use const true;
use yii\web\IdentityInterface;

class JWTAuth
{
    public $ttl = 3600;
    public $hostInfo = 'www.example.com';

    public function fromUser(IdentityInterface $user)
    {
        $id = $user->getId();
        $builder = new Builder();
        $builder->setIssuer($this->hostInfo);
        $builder->setAudience('api');
        $builder->setId(123, true);
        $builder->setIssuedAt(time());
        $builder->setNotBefore(time());
        $builder->setExpiration($this->ttl);
        $builder->set('user_id', $id);
//        $builder->sign($this->getSinger());
        $token = $builder->getToken();

        return $token;
    }

    public function create()
    {

    }

    protected function getSinger()
    {
        return new Sha256();
    }
}