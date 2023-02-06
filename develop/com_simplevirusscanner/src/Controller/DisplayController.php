<?php
 
namespace JohnSmith\Component\SimpleVirusScanner\Administrator\Controller;
 
defined('_JEXEC') or die;
 
use Joomla\CMS\MVC\Controller\BaseController;
 
/**
 * @package     Joomla.Administrator
 * @subpackage  com_simplevirusscanner
 *
 * @copyright   Copyright (C) 2021 John Smith. All rights reserved.
 * @license     GNU General Public License version 3; see LICENSE
 */
 
/**
 * Контроллер по умолчанию компонента SimpleVirusScanner
 *
 * @package     Joomla.Administrator
 * @subpackage  com_simpleVirusScanner
 */
class DisplayController extends BaseController {
    /**
     * Представление по умолчанию для метода отображения.
     *
     * @var string
     */
    protected $default_view = 'svs';
    
    public function display($cachable = false, $urlparams = array()) {
        return parent::display($cachable, $urlparams);
    }
    
}