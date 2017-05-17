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
 * 实现简单 jwt 认证
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
        $builder = $this->getBuilder();
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

    protected function getBuilder()
    {
        return new Builder();
    }

    public function getHostInfo()
    {
        if (Yii::$app->request->isConsoleRequest) {
            return $this->hostInfo;
        }
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

    protected function getParser()
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

    public function refresh()
    {
        $claims = $this->token->getClaims();
        $builder = $this->getBuilder();
        foreach ($claims as $claim => $value) {
            $builder->set($claim, $value);
        }
        $time = time();
        $builder->setIssuedAt($time);
        $builder->setNotBefore($time);
        $builder->setExpiration($this->ttl);
        $builder->sign($this->getSinger(), $this->getSecret());
        return $builder->getToken();
    }
}