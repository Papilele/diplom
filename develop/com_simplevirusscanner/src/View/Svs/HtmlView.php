<?php
 
namespace JohnSmith\Component\SimpleVirusScanner\Administrator\View\Svs;
 
defined('_JEXEC') or die;
 
use Joomla\CMS\MVC\View\HtmlView as BaseHtmlView;
 
/**
 * @package     Joomla.Administrator
 * @subpackage  com_simpleVirusScanner
 *
 * @copyright   Copyright (C) 2021 John Smith. All rights reserved.
 * @license     GNU General Public License version 3; see LICENSE
 */

class HtmlView extends BaseHtmlView {
    
    /**
     * Отображение основного вида "Site Scanner" 
     *
     * @param   string  $tpl  Имя файла шаблона для анализа; автоматический поиск путей к шаблону.
     * @return  void
     */
    function display($tpl = null) {
        parent::display($tpl);
    }
 
 
}