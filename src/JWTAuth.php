<?php
namespace symo\JWTAuth;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Token;
use symo\JWTAuth\Exceptions\JWTException;
use symo\JWTAuth\Exceptions\TokenExpiredException;
use symo\JWTAuth\Exceptions\TokenInvalidException;
use Yii;
use yii\web\IdentityInterface;
use function is_null;
use function time;

/**
 *
 */
class JWTAuth
{
    public $ttl = 3600;
    public $secret = '';
    public $hostInfo = '';

    /** @var Token */
    private $token;

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
        $builder->sign($this->getSinger(), $this->getSecret());
        $token = $builder->getToken();

        return $token;
    }

    public function getHostInfo()
    {
        $this->hostInfo= is_null(Yii::$app->request->hostInfo) ? $this->hostInfo : Yii::$app->request->hostInfo;
        return $this->hostInfo;
    }

    protected function getSinger()
    {
        return new Sha256();
    }

    public function getSecret()
    {
        if (empty($this->secret)) {
            $this->secret = Yii::$app->security->generateRandomString();
        }
        return $this->secret;
    }

    public function parseToken(string $token)
    {
        $this->token = $this->getParser()->parse($token);
        return $this;
    }

    public function getParser()
    {
        return new Parser();
    }

    public function authenticate()
    {
        if ($this->token->isExpired()) {
            throw new TokenExpiredException();
        }
        if (!$this->token->verify($this->getSinger(), $this->secret)) {
            throw new TokenInvalidException();
        }
        return $this->token;
    }
}