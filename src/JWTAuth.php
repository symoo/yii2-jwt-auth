<?php
namespace symo\JWTAuth;

use function is_null;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Token;
use symo\JWTAuth\Exceptions\JWTException;
use symo\JWTAuth\Exceptions\TokenExpiredException;
use symo\JWTAuth\Exceptions\TokenInvalidException;
use function time;
use const true;
use Yii;
use yii\web\IdentityInterface;

/**
 *
 */
class JWTAuth
{
    public $ttl = 3600;
    public $secret = 'aaaa';
    public $hostInfo = 'www.example.com';

    /** @var Token */
    private $tokenObj;

    public function fromUser(IdentityInterface $user)
    {
        $uid = $user->getId();
        if (empty($uid)) {
            throw new JWTException('user id can not be null');
        }
        $builder = new Builder();
        $builder->setIssuer($this->getHostInfo());
//        $builder->setAudience('api');
//        $builder->setId(123, true);
        $builder->setIssuedAt(time());
        $builder->setSubject($uid);
        $builder->setNotBefore(time());
        $builder->setExpiration(time() + $this->ttl);
        $builder->sign($this->getSinger(), $this->secret);
        $token = $builder->getToken();

        return $token;
    }

    public function validate()
    {

    }

    public function parserToken(string $token)
    {
        $this->tokenObj = $this->getParser()->parse($token);
        return $this;
    }

    public function authenticate()
    {
        if ($this->tokenObj->isExpired()) {
            throw new TokenExpiredException();
        }
        if (! $this->tokenObj->verify($this->getSinger(), $this->secret)) {
            throw new TokenInvalidException();
        }
        $id = $this->tokenObj->getClaim('sub');
        return $id;
    }

    public function getHostInfo()
    {
        $this->hostInfo= is_null(Yii::$app->request->hostInfo) ? $this->hostInfo : Yii::$app->request->hostInfo;
        return $this->hostInfo;
    }

    public function getParser()
    {
        return new Parser();
    }

    protected function getSinger()
    {
        return new Sha256();
    }
}