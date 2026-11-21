<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\migrations;

use Yii;
use yii\db\Migration;
use yii\db\Query;

/**
 * Version 3.0:
 * - tokens and codes are stored as SHA-256 hashes, existing ones are hashed in place and stay valid;
 * - client secrets are stored as bcrypt hashes, existing ones are hashed in place;
 * - used codes and refresh tokens are kept to detect reuse;
 * - nullable created_by/updated_by, indexes on user_id and client_id.
 *
 * Irreversible: hashes cannot be turned back into tokens and secrets.
 */
class m261123_120000_oauth_v3 extends Migration
{
    /**
     * @var int bcrypt cost of the client secret hashes, the same as Client::$secretHashCost
     */
    public $secretHashCost = 10;

    public function safeUp()
    {
        $sqlite = $this->db->driverName === 'sqlite';
        $tokens = [
            '{{%oauth2_access_token}}' => 'access_token',
            '{{%oauth2_refresh_token}}' => 'refresh_token',
            '{{%oauth2_authorization_code}}' => 'authorization_code',
        ];
        foreach ($tokens as $table => $column) {
            // SQLite does not limit string length and cannot alter columns
            if (!$sqlite) {
                $this->alterColumn($table, $column, $this->string(64)->notNull());
            }
            $this->hashColumn($table, $column, function ($value) {
                return strlen($value) === 64 && ctype_xdigit($value) ? null : hash('sha256', $value);
            });
            $this->createIndex("ix_{$column}_client_id_user_id", $table, ['client_id', 'user_id']);
        }
        $this->addColumn('{{%oauth2_refresh_token}}', 'used', $this->integer()->null());
        $this->addColumn('{{%oauth2_authorization_code}}', 'used', $this->integer()->null());

        $this->hashColumn('{{%oauth2_client}}', 'client_secret', function ($value) {
            if ($value === '' || preg_match('/^\$2[axy]\$\d\d\$/', $value)) {
                return null;
            }
            return Yii::$app->security->generatePasswordHash($value, $this->secretHashCost);
        }, 'client_id');

        if (!$sqlite) {
            $this->alterColumn('{{%oauth2_client}}', 'created_by', $this->integer()->null());
            $this->alterColumn('{{%oauth2_client}}', 'updated_by', $this->integer()->null());
        }
    }

    /**
     * Replaces the values of a column; the callback returns the new value or null to keep it.
     * @param string $table
     * @param string $column
     * @param callable $hash
     * @param string|null $key primary key column, the column itself by default
     * @return void
     */
    private function hashColumn($table, $column, callable $hash, $key = null)
    {
        $key = $key ?: $column;
        $rows = (new Query())->select(array_unique([$key, $column]))->from($table)->each(500, $this->db);
        foreach ($rows as $row) {
            $value = call_user_func($hash, (string)$row[$column]);
            if ($value !== null) {
                $this->db->createCommand()->update($table, [$column => $value], [$key => $row[$key]])->execute();
            }
        }
    }

    public function safeDown()
    {
        echo "m261123_120000_oauth_v3 cannot be reverted: tokens and secrets are hashed.\n";
        return false;
    }
}
