<?php
/**
 * @author @jayS-de <jens.schulze@commercetools.de>
 */


namespace Nelmio\SecurityBundle;


interface EncrypterInterface
{
    public function encrypt($input);
    public function decrypt($input);
}
