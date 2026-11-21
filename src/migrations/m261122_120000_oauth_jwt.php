<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\migrations;

use yii\db\Migration;

/**
 * Adds the client public key for JWT assertions (RFC 7523).
 */
class m261122_120000_oauth_jwt extends Migration
{
    public function safeUp()
    {
        $this->addColumn('{{%oauth2_client}}', 'public_key', $this->text()->null());
    }

    public function safeDown()
    {
        $this->dropColumn('{{%oauth2_client}}', 'public_key');
    }
}
