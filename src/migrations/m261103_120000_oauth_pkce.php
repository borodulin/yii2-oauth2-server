<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\migrations;

use yii\db\Migration;

/**
 * Adds PKCE (RFC 7636) columns to authorization codes.
 */
class m261103_120000_oauth_pkce extends Migration
{
    public function safeUp()
    {
        $this->addColumn('{{%oauth2_authorization_code}}', 'code_challenge', $this->string(128)->null());
        $this->addColumn('{{%oauth2_authorization_code}}', 'code_challenge_method', $this->string(10)->null());
    }

    public function safeDown()
    {
        $this->dropColumn('{{%oauth2_authorization_code}}', 'code_challenge_method');
        $this->dropColumn('{{%oauth2_authorization_code}}', 'code_challenge');
    }
}
