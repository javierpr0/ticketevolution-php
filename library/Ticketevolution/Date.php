<?php
/**
 * Ticketevolution Framework
 *
 * LICENSE
 *
 * This source file is subject to the new BSD license that is bundled
 * with this package in the file LICENSE.txt.
 * It is also available through the world-wide-web at this URL:
 * http://teamonetickets.com/software/ticket-evolution-framework-for-php/LICENSE.txt
 * If you did not receive a copy of the license and are unable to
 * obtain it through the world-wide-web, please send an email
 * to license@teamonetickets.com so we can send you a copy immediately.
 *
 * @category    Ticketevolution
 * @package     Ticketevolution_Date
 * @author      J Cobb <j@teamonetickets.com>
 * @author      Jeff Churchill <jeff@teamonetickets.com>
 * @copyright   Copyright (c) 2011 Team One Tickets & Sports Tours, Inc. (http://www.teamonetickets.com)
 * @license     http://teamonetickets.com/software/ticket-evolution-framework-for-php/LICENSE.txt     New BSD License
 * @version     $Id: Date.php 28 2011-05-09 22:53:01Z jcobb $
 */


/**
 * Include needed Date classes
 */
require_once 'Zend/Date.php';


/**
 * Extends Zend_Date with some handy constants and also allows for easy handling
 * of "TBA" event times.
 * 
 * @category    Ticketevolution
 * @package     Ticketevolution_Date
 * @copyright   Copyright (c) 2011 Team One Tickets & Sports Tours, Inc. (http://www.teamonetickets.com)
 * @license     http://teamonetickets.com/software/ticket-evolution-framework-for-php/LICENSE.txt     New BSD License
 */
class Ticketevolution_Date extends Zend_Date
{
    // These are here for convenience
    const MYSQL_DATETIME        = 'YYYY-MM-dd HH:mm:ss';
    const MYSQL_DATE            = 'YYYY-MM-dd';
    const MYSQL_TIME            = 'HH:mm:ss';

    const DATETIME_FULL_NOTZ    = 'EEEE, MMMM d, YYYY H:mm:ss a';

    const DATETIME_EBAY         = 'YYYY-MM-ddTHH:mm:ss.S';

    const DATE_FULL_US          = 'EEEE, MMMM d, YYYY';
    const DATE_LONG_US          = 'MMMM d, YYYY';

    const TBA_DISPLAY   = 'TBA';

    private $_locale  = null;

    // Fractional second variables
    private $_fractional = 0;
    private $_precision  = 3;

    private static $_options = array(
        'format_type'  => 'iso',      // format for date strings 'iso' or 'php'
        'fix_dst'      => true,       // fix dst on summer/winter time change
        'extend_month' => false,      // false - addMonth like SQL, true like excel
        'cache'        => null,       // cache to set
        'timesync'     => null        // timesync server to set
    );


    /**
     * Does exactly what Zend_Date does except that after setting the intial date/time
     * we check to see if it contains times that are known to be "TBA" for events
     * such as Event Inventory's '23:59:20' and '23:59:59' and if so it resets
     * the time to be '00:00:00' which is what we use as TBA.
     *
     * @param  string|integer|Zend_Date|array  $date    OPTIONAL Date value or value of date part to set
     *                                                 ,depending on $part. If null the actual time is set
     * @param  string                          $part    OPTIONAL Defines the input format of $date
     * @param  string|Zend_Locale              $locale  OPTIONAL Locale for parsing input
     * @return Zend_Date
     * @throws Zend_Date_Exception
     */
    public function __construct($date = null, $part = null, $locale = null)
    {
        parent::__construct($date, $part, $locale);
        
        if($this->get('HH:mm') === '23:59') {
            // This is an EventInventory TBA time
            // Set the time to '00:00:00'
            $this->set($this->get(self::DATES));
        }
    }


    /**
     * A "replacement" for the standard "get()" method that attempts to strip
     * time information from the requested format if the time appears to be for 
     * a TBA event and replace it with a 'TBA' string
     *
     * @param  string              $part    OPTIONAL Part of the date to return, if null the timestamp is returned
     * @param  string|Zend_Locale  $locale  OPTIONAL Locale for parsing input
     * @return string  date or datepart
     */
    public function getTbaSafe($part = null, $locale = null)
    {
        if($this->get('HH:mm') === '00:00') {
            // This time is for a TBA event
            $patterns = array('/[HhmSsWTa:]+/', '/ $/');
            $replacements = array('');
            $partCleaned = preg_replace($patterns, $replacements, $part);
            return $this->get($partCleaned, $locale) . ' ' . self::TBA_DISPLAY;
        }
        return $this->get($part, $locale);
    }

}
