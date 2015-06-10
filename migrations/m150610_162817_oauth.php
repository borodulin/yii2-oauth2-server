<?php
/**
 * @link https://github.com/borodulin/yii2-oauth-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth-server/blob/master/LICENSE
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
        $this->createTable('{{%oauth_client}}', [
                'client_id' => Schema::TYPE_STRING . '(80) NOT NULL',
                'client_secret' => Schema::TYPE_STRING . '(80) NOT NULL',
                'redirect_uri' => Schema::TYPE_TEXT . ' NOT NULL',
                'grant_types' => Schema::TYPE_TEXT . '(80) NOT NULL',
                'scopes' => Schema::TYPE_TEXT,
                'user_id' => Schema::TYPE_INTEGER . ' NOT NULL',
                'expires' => Schema::TYPE_INTEGER . ' NOT NULL',
                'scopes' => Schema::TYPE_TEXT,
                'public_key' => Schema::TYPE_TEXT,
                'PRIMARY KEY (client_id)',
        ]);
        
        $this->createTable('{{%oauth_access_token}}', [
                'access_token' => Schema::TYPE_STRING . '(40) NOT NULL',
                'client_id' => Schema::TYPE_STRING . '(80) NOT NULL',
                'user_id' => Schema::TYPE_INTEGER . ' NOT NULL',
                'expires' => Schema::TYPE_INTEGER . ' NOT NULL',
                'scopes' => Schema::TYPE_TEXT,
                'PRIMARY KEY (access_token)',
        ]);
        $this->addForeignKey('fk_oauth_access_token_oauth_client_client_id', '{{%oauth_access_token}}', 'client_id', '{{%oauth_client}}', 'client_id', 'cascade', 'cascade');

        $this->createTable('{{%oauth_refresh_token}}', [
                'refresh_token' => Schema::TYPE_STRING . '(40) NOT NULL',
                'client_id' => Schema::TYPE_STRING . '(80) NOT NULL',
                'user_id' => Schema::TYPE_INTEGER . ' NOT NULL',
                'expires' => Schema::TYPE_INTEGER . ' NOT NULL',
                'scopes' => Schema::TYPE_TEXT,
                'PRIMARY KEY (refresh_token)',
        ]);
        $this->addForeignKey('fk_oauth_refresh_token_oauth_client_client_id', '{{%oauth_refresh_token}}', 'client_id', '{{%oauth_client}}', 'client_id', 'cascade', 'cascade');
        
        $this->createTable('{{%oauth_authorization_code}}', [
                'authorization_code' => Schema::TYPE_STRING . '(40) NOT NULL',
                'client_id' => Schema::TYPE_STRING . '(80) NOT NULL',
                'user_id' => Schema::TYPE_INTEGER . ' NOT NULL',
                'redirect_uri' => Schema::TYPE_TEXT . ' NOT NULL',
                'expires' => Schema::TYPE_INTEGER . ' NOT NULL',
                'scopes' => Schema::TYPE_TEXT,
                'id_token' => Schema::TYPE_STRING . '(40) NOT NULL',
                'PRIMARY KEY (authorization_code)',
        ]);
        $this->addForeignKey('fk_oauth_authorization_code_oauth_client_client_id', '{{%oauth_authorization_code}}', 'client_id', '{{%oauth_client}}', 'client_id', 'cascade', 'cascade');
        
    }
    
    public function safeDown()
    {
        $this->dropTable('{{%oauth_authorization_code}}');
        $this->dropTable('{{%oauth_refresh_token}}');
        $this->dropTable('{{%oauth_access_token}}');
        $this->dropTable('{{%oauth_client}}');
    }
}
