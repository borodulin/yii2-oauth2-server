<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

use conquer\oauth2\OAuth2;
use yii\db\Migration;

/**
 *
 * @author Andrey Borodulin
 *
 */
class m150610_162817_oauth extends Migration
{

    /**
     * @var OAuth2
     */
    private $oauth2;

    /**
     * @throws \yii\base\InvalidConfigException
     */
    public function init()
    {
        $this->oauth2 = Yii::$app->get('oauth2', false);
        if (!$this->oauth2 instanceof OAuth2) {
            $this->oauth2 = Yii::createObject(Oauth2::class);
        }
        $this->db = $this->oauth2->db;
    }

    /**
     * @return bool|void
     */
    public function safeUp()
    {
        $this->createTable($this->oauth2->clientTable, [
            'client_id' => $this->string(80)->notNull(),
            'client_secret' => $this->string(80)->notNull(),
            'redirect_uri' => $this->text()->notNull(),
            'grant_type' => $this->text(),
            'scope' => $this->text(),
            'created_at' => $this->integer()->notNull(),
            'updated_at' => $this->integer()->notNull(),
            'created_by' => $this->integer(),
            'updated_by' => $this->integer(),
            'PRIMARY KEY (client_id)',
        ]);

        $this->createTable($this->oauth2->accessTokenTable, [
            'access_token' => $this->string(40)->notNull(),
            'client_id' => $this->string(80)->notNull(),
            'user_id' => $this->integer(),
            'expires' => $this->integer()->notNull(),
            'scope' => $this->text(),
            'PRIMARY KEY (access_token)',
        ]);

        $this->createTable($this->oauth2->refreshTokenTable, [
            'refresh_token' => $this->string(40)->notNull(),
            'client_id' => $this->string(80)->notNull(),
            'user_id' => $this->integer(),
            'expires' => $this->integer()->notNull(),
            'scope' => $this->text(),
            'PRIMARY KEY (refresh_token)',
        ]);

        $this->createTable($this->oauth2->authorizationCodeTable, [
            'authorization_code' => $this->string(40)->notNull(),
            'client_id' => $this->string(80)->notNull(),
            'user_id' => $this->integer(),
            'redirect_uri' => $this->text()->notNull(),
            'expires' => $this->integer()->notNull(),
            'scope' => $this->text(),
            'PRIMARY KEY (authorization_code)',
        ]);

        $this->addforeignkey('fk_refresh_token_oauth2_client_client_id', $this->oauth2->refreshTokenTable, 'client_id', $this->oauth2->clientTable, 'client_id', 'cascade', 'cascade');
        $this->addforeignkey('fk_authorization_code_oauth2_client_client_id', $this->oauth2->authorizationCodeTable, 'client_id', $this->oauth2->clientTable, 'client_id', 'cascade', 'cascade');
        $this->addforeignkey('fk_access_token_oauth2_client_client_id', $this->oauth2->accessTokenTable, 'client_id', $this->oauth2->clientTable, 'client_id', 'cascade', 'cascade');

        $this->createIndex('ix_authorization_code_expires', $this->oauth2->authorizationCodeTable, 'expires');
        $this->createIndex('ix_refresh_token_expires', $this->oauth2->refreshTokenTable, 'expires');
        $this->createIndex('ix_access_token_expires', $this->oauth2->accessTokenTable, 'expires');
    }

    public function safeDown()
    {
        $this->dropTable($this->oauth2->authorizationCodeTable);
        $this->dropTable($this->oauth2->refreshTokenTable);
        $this->dropTable($this->oauth2->accessTokenTable);
        $this->dropTable($this->oauth2->clientTable);
    }
}
