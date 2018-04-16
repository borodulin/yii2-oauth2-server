<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

use conquer\oauth2\OAuth2;
use yii\db\Migration;

/**
 * @author Andrey Borodulin
 */
class m150610_162817_oauth extends Migration
{
    /**
     * @throws \yii\base\InvalidConfigException
     */
    public function init()
    {
        $this->db = OAuth2::instance()->db;
    }

    /**
     * @return bool|void
     * @throws \yii\base\InvalidConfigException
     */
    public function safeUp()
    {
        $oauth2 = OAuth2::instance();
        $this->createTable($oauth2->clientTable, [
            'client_id' => $this->string(80)->notNull(),
            'client_secret' => $this->string(80)->notNull(),
            'redirect_uri' => $this->text()->notNull(),
            'grant_type' => $this->text(),
            'scope' => $this->text(),
            'created_at' => $this->integer(),
            'updated_at' => $this->integer(),
            'created_by' => $this->integer(),
            'updated_by' => $this->integer(),
            'PRIMARY KEY (client_id)',
        ]);

        $this->createTable($oauth2->accessTokenTable, [
            'access_token' => $this->string(40)->notNull(),
            'client_id' => $this->string(80)->notNull(),
            'user_id' => $this->integer(),
            'expires' => $this->integer()->notNull(),
            'scope' => $this->text(),
            'PRIMARY KEY (access_token)',
        ]);

        $this->createTable($oauth2->refreshTokenTable, [
            'refresh_token' => $this->string(40)->notNull(),
            'client_id' => $this->string(80)->notNull(),
            'user_id' => $this->integer(),
            'expires' => $this->integer()->notNull(),
            'scope' => $this->text(),
            'PRIMARY KEY (refresh_token)',
        ]);

        $this->createTable($oauth2->authorizationCodeTable, [
            'authorization_code' => $this->string(40)->notNull(),
            'client_id' => $this->string(80)->notNull(),
            'user_id' => $this->integer(),
            'redirect_uri' => $this->text()->notNull(),
            'expires' => $this->integer()->notNull(),
            'scope' => $this->text(),
            'PRIMARY KEY (authorization_code)',
        ]);

        $this->addforeignkey('fk_refresh_token_oauth2_client_client_id', $oauth2->refreshTokenTable, 'client_id', $oauth2->clientTable, 'client_id', 'cascade', 'cascade');
        $this->addforeignkey('fk_authorization_code_oauth2_client_client_id', $oauth2->authorizationCodeTable, 'client_id', $oauth2->clientTable, 'client_id', 'cascade', 'cascade');
        $this->addforeignkey('fk_access_token_oauth2_client_client_id', $oauth2->accessTokenTable, 'client_id', $oauth2->clientTable, 'client_id', 'cascade', 'cascade');

        $this->createIndex('ix_authorization_code_expires', $oauth2->authorizationCodeTable, 'expires');
        $this->createIndex('ix_refresh_token_expires', $oauth2->refreshTokenTable, 'expires');
        $this->createIndex('ix_access_token_expires', $oauth2->accessTokenTable, 'expires');
    }

    /**
     * @return bool|void
     * @throws \yii\base\InvalidConfigException
     */
    public function safeDown()
    {
        $oauth2 = OAuth2::instance();
        $this->dropTable($oauth2->authorizationCodeTable);
        $this->dropTable($oauth2->refreshTokenTable);
        $this->dropTable($oauth2->accessTokenTable);
        $this->dropTable($oauth2->clientTable);
    }
}
