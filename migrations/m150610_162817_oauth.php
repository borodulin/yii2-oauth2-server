<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

use yii\db\Schema;
use yii\db\Migration;

/**
 *
 * @author Andrey Borodulin
 *
 */
class m150610_162817_oauth extends Migration
{
    // Use safeUp/safeDown to run migration code within a transaction
    public function safeUp()
    {
        $this->createTable('{{%oauth2_client}}', [
            'client_id' => Schema::TYPE_STRING . '(80) NOT NULL',
            'client_secret' => Schema::TYPE_STRING . '(80) NOT NULL',
            'redirect_uri' => Schema::TYPE_TEXT . ' NOT NULL',
            'grant_type' => Schema::TYPE_TEXT,
            'scope' => Schema::TYPE_TEXT,
            'created_at' => Schema::TYPE_INTEGER . ' NOT NULL',
            'updated_at' => Schema::TYPE_INTEGER . ' NOT NULL',
            'created_by' => Schema::TYPE_INTEGER . ' NOT NULL',
            'updated_by' => Schema::TYPE_INTEGER . ' NOT NULL',
            'PRIMARY KEY (client_id)',
        ]);

        $this->createTable('{{%oauth2_access_token}}', [
            'access_token' => Schema::TYPE_STRING . '(40) NOT NULL',
            'client_id' => Schema::TYPE_STRING . '(80) NOT NULL',
            'user_id' => Schema::TYPE_INTEGER,
            'expires' => Schema::TYPE_INTEGER . ' NOT NULL',
            'scope' => Schema::TYPE_TEXT,
            'PRIMARY KEY (access_token)',
        ]);

        $this->createTable('{{%oauth2_refresh_token}}', [
            'refresh_token' => Schema::TYPE_STRING . '(40) NOT NULL',
            'client_id' => Schema::TYPE_STRING . '(80) NOT NULL',
            'user_id' => Schema::TYPE_INTEGER,
            'expires' => Schema::TYPE_INTEGER . ' NOT NULL',
            'scope' => Schema::TYPE_TEXT,
            'PRIMARY KEY (refresh_token)',
        ]);

        $this->createTable('{{%oauth2_authorization_code}}', [
            'authorization_code' => Schema::TYPE_STRING . '(40) NOT NULL',
            'client_id' => Schema::TYPE_STRING . '(80) NOT NULL',
            'user_id' => Schema::TYPE_INTEGER,
            'redirect_uri' => Schema::TYPE_TEXT . ' NOT NULL',
            'expires' => Schema::TYPE_INTEGER . ' NOT NULL',
            'scope' => Schema::TYPE_TEXT,
            'PRIMARY KEY (authorization_code)',
        ]);

        $this->addforeignkey('fk_refresh_token_oauth2_client_client_id', '{{%oauth2_refresh_token}}', 'client_id', '{{%oauth2_client}}', 'client_id', 'cascade', 'cascade');
        $this->addforeignkey('fk_authorization_code_oauth2_client_client_id', '{{%oauth2_authorization_code}}', 'client_id', '{{%oauth2_client}}', 'client_id', 'cascade', 'cascade');
        $this->addforeignkey('fk_access_token_oauth2_client_client_id', '{{%oauth2_access_token}}', 'client_id', '{{%oauth2_client}}', 'client_id', 'cascade', 'cascade');

        $this->createIndex('ix_authorization_code_expires', '{{%oauth2_authorization_code}}', 'expires');
        $this->createIndex('ix_refresh_token_expires', '{{%oauth2_refresh_token}}', 'expires');
        $this->createIndex('ix_access_token_expires', '{{%oauth2_access_token}}', 'expires');
    }

    public function safeDown()
    {
        $this->dropTable('{{%oauth2_authorization_code}}');
        $this->dropTable('{{%oauth2_refresh_token}}');
        $this->dropTable('{{%oauth2_access_token}}');
        $this->dropTable('{{%oauth2_client}}');
    }
}
