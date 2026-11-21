<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2;

use Yii;
use yii\i18n\PhpMessageSource;

/**
 * Registers the "conquer/oauth2" message category, so that the application does not have to.
 */
class Translations
{
    const CATEGORY = 'conquer/oauth2';

    /**
     * Adds the message source unless the application configured one.
     * @return void
     */
    public static function register()
    {
        if (Yii::$app === null || !Yii::$app->has('i18n')) {
            return;
        }
        $i18n = Yii::$app->getI18n();
        if (!isset($i18n->translations[self::CATEGORY]) && !isset($i18n->translations['conquer/*'])) {
            $i18n->translations[self::CATEGORY] = [
                'class' => PhpMessageSource::class,
                'sourceLanguage' => 'en-US',
                'basePath' => __DIR__ . '/messages',
                'fileMap' => [self::CATEGORY => 'oauth2.php'],
            ];
        }
    }
}
