<?php
/**
 * @link https://github.com/borodulin/yii2-oauth-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth-server/blob/master/LICENSE
 */

namespace app\oauth\models;

use Yii;

/**
 * This is the model class for table "oauth_scope".
 *
 * @property string $scope
 * @property integer $is_default
 */
class OauthScope extends \yii\db\ActiveRecord
{
    /**
     * @inheritdoc
     */
    public static function tableName()
    {
        return '{{%oauth_scope}}';
    }

    /**
     * @inheritdoc
     */
    public function rules()
    {
        return [
            [['scope'], 'required'],
            [['is_default'], 'integer'],
            [['scope'], 'string', 'max' => 80]
        ];
    }

    /**
     * @inheritdoc
     */
    public function attributeLabels()
    {
        return [
            'scope' => 'Scope',
            'is_default' => 'Is Default',
        ];
    }
}
