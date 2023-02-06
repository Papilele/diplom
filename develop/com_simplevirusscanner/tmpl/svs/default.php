<?php
 
/**
 * @package     Joomla.Administrator
 * @subpackage  com_simpleVirusScanner
 *
 * @copyright   Copyright (C) 2021 John Smith. All rights reserved.
 * @license     GNU General Public License version 3; see LICENSE
 */

defined('_JEXEC') or die('Нет прямого доступа к этому файлу');

define('SVS_FILE_EXTENSIONS', "php,inc");
define('SVS_FORBIDDEN_DIRS', "img,images,upload,tmp,assets");
define('SVS_MAX_FILESIZE', 2100000);
define('SVS_VERSION', "2.44");
?>
<h2>Результат сканирования:</h2>

<?
class RainbowCounter
{
	var $rainbowColors = ["#9b350c", "#009688", "#607d8b", "#03a9f4", "#9c27b0", "#673ab7", "#e91e63", "#ff9800", "#795548", "#cddc39", "#681676", "#4983dd", "#49ddd1", "#9b700c", "#e45023", "#a80b63", "#db246a", "#dd7128", "#e95a2f"];
	var $rainbowCnt = 0;
	var $isWeb = true;

	public function __construct($isWeb)
	{
		$this->isWeb = $isWeb;
	}

	public function rainbow($text)
	{
		if (!$this->isWeb) return $text;

		$text = "<span style='color:" . $this->rainbowColors[$this->rainbowCnt] . ";'>$text</span>";

		return $text;
	}

	public function reset()
	{
		$this->rainbowCnt = 0;
	}

	public function inc()
	{
		if ($this->rainbowCnt < count($this->rainbowColors) - 1) {
			$this->rainbowCnt++;
		} else {
			$this->rainbowCnt = 0;
		}
	}
}

class Scanner
{
	var $rootFolder = "";
	var $isWeb = true;
	var $scanList = [];
	var $forbiddenDirs = [];
	var $scanExtentions = [];
	private $selfSize = 0;
	private $selfCRC = "";
	private $totalFilesScanned = 0;
	private $totalFilesSuspicious = 0;
	private $totalFilesExcluded = 0;
	var $noSort = false;

	private $minScore = 6;

	public function __construct($rootFolder = __DIR__)
	{
		$this->rootFolder = $_SERVER['DOCUMENT_ROOT'];
		$this->isWeb = (php_sapi_name() !== 'cli');
		$options =  getopt('', ['html::', 'm::', 'root::', 'nosort::']);

		if (isset($options['html'])) $this->isWeb = true;
		if (isset($_GET['plaintext'])) $this->isWeb = false;
		if (isset($options['root'])) $this->rootFolder = $options['root'];
		if (isset($options['nosort'])) $this->noSort = true;
		if (isset($_GET['nosort'])) $this->noSort = true;
		if (isset($options['m'])) $this->minScore = $options['m'];
		if (isset($_GET['m'])) $this->minScore = $_GET['m'];

		$this->selfSize = filesize(__FILE__);
		$this->selfCRC = crc32(file_get_contents(__FILE__));

 		$this->forbiddenDirs = explode(",", SVS_FORBIDDEN_DIRS);

		$exts = explode(",", SVS_FILE_EXTENSIONS);
		$this->scanExtentions = "~\.(" . join("|", $exts) . ")$~i";
	}

	public function error($errorText)
	{
		if ($this->isWeb) {
			echo "<span style='color:red'>ERROR: </span><br>" . $errorText . "<br>";
		} else {
			echo ">> ERROR: " . $errorText . "\n";
		}
	}

	private function out($message)
	{
		if ($this->isWeb) {
			echo $message . "<br>";
		} else {
			echo $message . "\n";
		}
	}

	public function buildScanList($startDir = "", $level = 0)
	{
		$dirToScan = ($startDir != "") ? $this->rootFolder . "/" . $startDir : $this->rootFolder;
		if ($handle = opendir($dirToScan)) {
			$exts = $this->scanExtentions;

			$arrDirs  = [];
			$arrFiles = [];

			while (false !== ($entry = readdir($handle))) {
				if ($entry != "." && $entry != "..") {
					if (is_dir($dirToScan . "/" . $entry) && !is_link($dirToScan . "/" . $entry)) {
						$arrDirs[] = $entry;
					} else {
					
						if (preg_match($exts, $entry) > 0 && $dirToScan . "/" . $entry !== __FILE__) {
							$arrFiles[] = $entry;
						}
					}
				}
			}

			closedir($handle);
			asort($arrDirs);
			asort($arrFiles);

			foreach ($arrFiles as $entry) {
				$dirPath = ($startDir != "") ? $startDir : "/";
				$this->totalFilesScanned++;
				$id = $this->totalFilesScanned;
				$this->scanList[$id]['dir'] = $dirPath;
				$this->scanList[$id]['name'] = $entry;
				$this->scanList[$id]['score'] = 0;
				$this->scanList[$id]['level'] = $level;
				$this->scanList[$id]['diag'] = [];
			}

			unset($arrFiles);

			foreach ($arrDirs as $entry) {
				$this->buildScanList($startDir . "/" . $entry, $level + 1);
			}
		} else {
			$this->error("Cannot open root folder '" . $this->rootFolder . "'");
		}
	}

	function isExclusion($dirPath, $fileName)
	{
		$fullPath = ($dirPath == "/") ? $this->rootFolder : $this->rootFolder . $dirPath;
		$file = $fullPath . "/" . $fileName;
		$arrWhitelist = ['snusminer.php',
		'/administrator/components/com_akeeba/BackupEngine/Archiver/Jpa.php',
		'/administrator/components/com_akeeba/BackupEngine/Archiver/Jps.php',
		'/administrator/components/com_akeeba/BackupEngine/Archiver/Zip.php',
		'/administrator/components/com_akeeba/BackupEngine/Postproc/Sugarsync.php',
		'/administrator/components/com_akeeba/restore.php',
		'/administrator/components/com_akeeba/View/Upload/tmpl/default.php',
		'/administrator/components/com_akeeba/View/Upload/tmpl/done.php',
		'/administrator/components/com_akeeba/View/Upload/tmpl/error.php',
		'/administrator/components/com_akeeba/View/Upload/tmpl/uploading.php',
		'/administrator/components/com_finder/helpers/indexer/stemmer/fr.php',
		'/administrator/components/com_joomlaupdate/views/upload/tmpl/captive.php',
		'/administrator/components/com_media/views/images/tmpl/default.php',
		'/image_uploader/localization.php',
		'/libraries/idna_convert/idna_convert.class.php',
		'/libraries/vendor/joomla/string/src/phputf8/native/core.php',
		'/modules/fileman/classes/general/sticker.php',
		'/modules/iblock/admin/iblock_edit.php',
		'/modules/iblock/admin/iblock_element_admin.php',
		'/modules/iblock/admin/iblock_list_admin.php',
		'/modules/iblock/admin/templates/iblock_subelement_list.php',
		'/modules/iblock/classes/general/comp_pricetools.php',
		'/modules/main/admin/group_edit.php',
		'/modules/main/admin/restore.php',
		'/modules/main/admin/site_checker.php',
		'/modules/main/classes/general/backup.php',
		'/modules/main/classes/general/cache_files.php',
		'/modules/main/classes/general/cache_html.php',
		'/modules/main/classes/general/punycode.php',
		'/modules/main/classes/general/usertypedbl.php',
		'/modules/main/classes/general/virtual_io_filesystem.php',
		'/modules/main/classes/general/zip.php',
		'/modules/main/lib/io/directory.php',
		'/modules/main/tools.php',
		'administrator/components/com_joomlaupdate/restore.php',
		'modules/defa.socialmediaposter/classes/general/idna_convert.class.php',
		'libraries/vendor/algo26-matthias/idna-convert/src/NamePrep/NamePrepData2008.php',
		'administrator/components/com_simplevirusscanner/tmpl/svs/default.php',
		];

		$isEx =  false;

		if ($fileName == __FILE__) {
			$isEx = true;
		}

		foreach($arrWhitelist as $wl) {
			if (strstr($file, $wl) !== false) {
				$isEx = true;
				break;
			}
		}
		return $isEx;
	}

	function scanFile($id)
	{
		$rbc = new RainbowCounter($this->isWeb);

		$entry = &$this->scanList[$id];
		$dirPath = $entry['dir'];
		$fileName = $entry['name'];

		foreach ($this->forbiddenDirs as $fd) {
			if (preg_match("~\/" . $fd . "[/$]~i", $dirPath) > 0) {
				$entry['score'] = $entry['score'] + 50;
				$entry['diag']['susp_dir'] = $rbc->rainbow('suspicious dir \''.$fd.'\'');
				break;
			}
		}
		$rbc->inc();


		$contents = "";
		$fullPath = ($dirPath == "/") ? $this->rootFolder : $this->rootFolder . $dirPath;
		if (filesize($fullPath . "/" . $fileName) < SVS_MAX_FILESIZE) {
			$contents = file_get_contents($fullPath . "/" . $fileName);
		} else {
			$this->error("File too big: " . $fullPath . "/" . $fileName. " (". filesize($fullPath . "/" . $fileName). ")");
			$entry['score'] = $entry['score'] + 50;
			$entry['diag']['too_big'] = $rbc->rainbow('file too big');
			return true;
		}
		$rbc->inc();

		if ($contents === false) {
			$this->error("Cannot read " . $fullPath . "/" . $fileName);
			$entry['score'] = $entry['score'] + 50;
			$entry['diag']['cant_read'] = $rbc->rainbow('can\'t read');
			return true;
		}
		$rbc->inc();

		if (preg_match('~(\\\x[a-z0-9]{2,3}){3,}~', $contents) > 0) {
			$entry['score'] = $entry['score'] + 10;
			$entry['diag']['esc_seq'] = $rbc->rainbow('escape sequence');
		}
		$rbc->inc();

		if (preg_match('~@\$\{\"~', $contents) > 0) {
			$entry['score'] = $entry['score'] + 30;
			$entry['diag']['weird_constr'] = $rbc->rainbow('weird construction');
		}
		$rbc->inc();

		$matches = [];
		$cnt = preg_match_all('~[a-zA-Z0-9]{35,}~', $contents);
		if ($cnt > 1) {
			$entry['score'] = $entry['score'] + 5 + floor($cnt / 5)*5;
			$entry['diag']['long_id'] = $rbc->rainbow('long identifier (x' . $cnt . ')');
		}
		$rbc->inc();

		if (preg_match('~base64_decode~', $contents) > 0) {
			$entry['score'] = $entry['score'] + 10;
			$entry['diag']['base64'] = $rbc->rainbow('base64_decode()');
		}
		$rbc->inc();

		if (preg_match('~php_uname~', $contents) > 0) {
			$entry['score'] = $entry['score'] + 20;
			$entry['diag']['php_uname'] = $rbc->rainbow('php_uname()');
		}
		$rbc->inc();

		$matches = [];
		$cnt = preg_match_all('~chr\(\d{2,3}\)~', $contents, $matches);
		if ($cnt > 0) {
			$entry['score'] = $entry['score'] + 5 + floor($cnt / 10)*5;
			$entry['diag']['chr'] = $rbc->rainbow('chr() (x' . $cnt . ')');
		}
		$rbc->inc();

		if (preg_match('~shell_exec\s*\(~', $contents) > 0) {
			$entry['score'] = $entry['score'] + 50;
			$entry['diag']['shell_exec'] = $rbc->rainbow('shell_exec()');
		}
		$rbc->inc();

		$matches = [];
		$cnt = preg_match_all('~chmod\s*\(~', $contents, $matches);
		if ($cnt > 0) {
			$entry['score'] = $entry['score'] + 10;
			$entry['diag']['chmod'] = $rbc->rainbow('chmod()');
		}
		$rbc->inc();

		if (preg_match('~\$[a-zA-Z0-9]{5,}\{\d{2}}~', $contents) > 0) {
			$entry['score'] = $entry['score'] + 30;
			$entry['diag']['weird_var'] = $rbc->rainbow('weird variables');
		}
		$rbc->inc();

		$matches = [];
		$cnt = preg_match_all('~0x[0-9A-F]{4}~', $contents, $matches);
		if ($cnt > 3) {
			$entry['score'] = $entry['score'] + 5 + floor($cnt / 20);
			$entry['diag']['hex'] = $rbc->rainbow('hex codes (x' . $cnt . ")");
		}
		$rbc->inc();

		$matches = [];
		$cnt = preg_match_all('~eval\(~', $contents, $matches);
		if ($cnt > 0) {
			$entry['score'] = $entry['score'] + 10 + floor($cnt / 5)*5;
			$entry['diag']['eval'] = $rbc->rainbow('eval()');
		}
		$rbc->inc();

		$matches = [];
		$cnt = preg_match_all('~fileperms\(~', $contents, $matches);
		if ($cnt > 0) {
			$entry['score'] = $entry['score'] + 10 + floor($cnt / 5)*5;
			$entry['diag']['fileperms'] = $rbc->rainbow('fileperms()');
		}
		$rbc->inc();

		if (preg_match('~gzinflate\(~', $contents) > 0) {
			$entry['score'] = $entry['score'] + 10;
			$entry['diag']['gzinflate'] = $rbc->rainbow('gzinflate()');
		}
		$rbc->inc();

		if (preg_match('~register_shutdown_function\(~', $contents) > 0) {
			$entry['score'] = $entry['score'] + 5;
			$entry['diag']['register_shutdown_function'] = $rbc->rainbow('register_shutdown_function()');
		}
		$rbc->inc();

		if (preg_match('~[^"a-zA-Z0-9_$]goto\s~', $contents) > 0) {
			$entry['score'] = $entry['score'] + 20;
			$entry['diag']['goto'] = $rbc->rainbow('goto');
		}
		$rbc->inc();

		if (preg_match('~enctype\s*=\s*[\'"]multipart/form-data[\'"]~i', $contents) > 0) {
			$entry['score'] = $entry['score'] + 5;
			$entry['diag']['upload'] = $rbc->rainbow('upload form');
		}
		$rbc->inc();

		if (preg_match('~include\s*\([^;]*\$_GET~Uis', $contents) > 0) {
			$entry['score'] = $entry['score'] + 50;
			$entry['diag']['include_get'] = $rbc->rainbow('include from $_GET');
		}
		$rbc->inc();

		foreach ($this->forbiddenDirs as $fd) {
			if (preg_match("~include\s*\([^;]*\/".$fd."[^a-zA-Z0-9]~is", $contents) > 0) {
				$entry['score'] = $entry['score'] + 50;
				$entry['diag']['susp_include'] = $rbc->rainbow('include in \''.$fd.'\'');
				break;
			}


		}
		$rbc->inc();

		if (preg_match('~\$USER->Authorize\([^\$]~', $contents) > 0) {
			$entry['score'] = $entry['score'] + 50;
			$entry['diag']['authorize'] = $rbc->rainbow('authorize()');
		}
		$rbc->inc();

		if (count($entry['diag']) > 2) {
			$entry['score'] = $entry['score'] + 20;
		}

		$entry['exclusion'] =  $this->isExclusion($dirPath, $fileName);
	}

	public function scanFiles()
	{
		foreach ($this->scanList as $id => $entry) {
				$this->scanFile($id);
		}
	}

	private function pre($var, $export =  false)
	{
		if ($this->isWeb) echo ("<pre>");

		if ($export) {
			var_export($var);
		} else {
			$this->out($var);
		}

		if ($this->isWeb) echo ("</pre>");
	}

	public function sortScanList(){
		global $noSort;
		$noSort = $this->noSort;

		function comp1($a, $b){
			global $noSort;
			if ($a["exclusion"] || $b["exclusion"] ) {
				if ($a["exclusion"] && $b["exclusion"]) {
					if ($noSort) return 0;
					return ($a["score"] > $b["score"]) ? -1 : 1;
				} else {
					return 1;
				}
			} else {
				if ($noSort) return 0;
				if ($a["score"] == $b["score"]) return 0;
				return ($a["score"] > $b["score"]) ? -1 : 1;
			}
		}

		usort($this->scanList, "comp1");
	}

	public function printScanList()
	{
		$marker = $this->isWeb ? "■" : "+";

		$this->out('<div class="black">Минимальная оценка безопасности: '.$this->minScore.'</div>');

		if ($this->isWeb) {
			ob_start();
			echo ("<html>
			<head>
			<title>Сканнирование сайта</title>
			<style>
			body {
				font-family: Arial;
				font-size: 18px;
				background-color: #1F3047;
				color: white;
				font-weight: 600;
			}

			.black {
				color: black !important;
			}

			tbody {
				background-color: #2E486B;
			}

			tr {
				border-bottom: 2px solid #1F3047;
			}

			table {
				font-family: Arial;
				font-size: 18px;
				margin: 0 auto;
			}

			th {
				background-color: #2E486B;
				padding: 10px;
				font-size: 24px;
			}

			td{
				border-bottom: solid 1px #3D618F;
				vertical-align: text-top;
				padding-right: 20px;
				height: 24px;
			}

			table tr td:nth-child(1) {
				text-align: left;
			}

			table tr td:nth-child(2) {
				text-align: right;
			}

			table tr td:nth-child(3) {
				font-size: 13px;
			}

			.directory {
				color: #F0EAD6;
			}

			.marker {
				color: #EB4C42;
				font-size: 30px;
			}
			.exclusion {
				color: #4caf50;
			}
			.file {
				border-right: 1px solid #1F3047;
			}
			.alerts {
				border-left: 1px solid #1F3047;
			}

			.lastmes {
				color: black;
			}
			</style>
			</head>
			<body>
			<table border='0' cellpadding='2' cellspacing='0'>
			<tr>
				<th class='file'>Файл</th>
				<th>Уровень опасности</th>
				<th class='alerts'>Обнаружены</th>
			</tr>
			");
		} else {
			$this->out("-- Запуск сканнера --");
		}

		foreach ($this->scanList as $entry) {
			$dir = $entry['dir'];
			$dirname = ($dir == "/" || $dir == "") ? "/" : substr($dir, 1) . "/";
			$dirname = $this->isWeb ? "<span class='directory'>" . $dirname . "</span>" : "" . $dirname . "";


			if ($entry['score'] > $this->minScore) {
				$markerCount = floor($entry['score'] / 10);
				if ($markerCount > 10) $markerCount = 10;

				if ($this->isWeb) {
					echo ("
						<tr>
							<td ".(($entry['exclusion']) ? " class='exclusion'" :	"").">$dirname<b>" . $entry['name'] . "</b> </td>
							<td>" . (($entry['exclusion']) ?
										" <span class='exclusion'>X</span>" :
										"<span class='marker'>".  str_repeat("$marker",  $markerCount) . "</span>") .
							" [".$entry['score']."]
							</td>
							<td>" . join(", ", $entry['diag']) . "</td>
						</tr>
						");
						ob_flush();
				} else {
					$name =  $entry['name'];
					$this->out((($entry['exclusion']) ? "X " : str_repeat("$marker",  $markerCount))  . " [".$entry['score']."] " . $dirname . $name .
						" [" . join(", ", $entry['diag']) . "]");
				}

				if ($entry['exclusion']) {
					$this->totalFilesExcluded++;
				} else {
					$this->totalFilesSuspicious++;
				}
			}

		}

		if ($this->isWeb) {
			echo ("</table>");
			ob_end_flush();
		}



		$this->out("<div class='lastmes'>Всего просканировано файлов " . $this->totalFilesScanned);
		$this->out("Из них потенциально опасных: " . $this->totalFilesSuspicious." + ".$this->totalFilesExcluded." исключения(-ий).");
		$this->out("Отчет предоставлен 'Site Scanner' " . date("Y-m-d H:i")."</div>");
	}
}

$scanner = new Scanner();
$scanner->buildScanList();
$scanner->scanFiles();
$scanner->sortScanList();
$scanner->printScanList();


