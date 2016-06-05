//
//  BLEController.swift
//  CryptoBluetooth
//
//  Created by Alexey on 5/06/2016.
//  Copyright © 2016 Alexey Zhilnikov. All rights reserved.
//

import Foundation
import CoreBluetooth

@objc protocol BLEControllerDelegate {
    optional func didBLEPowerOn()
    optional func didBLEPowerOff()
    optional func didBLEUpdateState(state: State.RawValue)
    optional func didBLEUpdateIcon(name: String)
    optional func didBLEUpdateValue1(value: Int)
    optional func didBLEUpdateValue2(value: Int)
    optional func didBLEUpdateText1(text: String)
    optional func didBLEUpdateID1(text: String)
    optional func didBLEUpdateID2(text: String)
    optional func didBLEUpdateList(list: [String: String])
    optional func didBLEUpdateValue3(value: Int)
    optional func didBLEUpdateText2(text: String)
    optional func didBLELoseBroadcast()
    optional func didBLEConnect()
    optional func didBLEFailConnect()
    optional func didBLEDisconnect()
    optional func didBLESendConfirmation(value: String)
}

let latestState             = "LatestState"
let latestValue1            = "LatestValue1"
let latestIcon              = "LatestIcon"
let latestValue2            = "LatestValue2"
let latestText              = "LatestText"
let latestID1               = "LatestID1"
let latestID2               = "LatestID2"
let latestList              = "LatestList"

let bleNo                   = "NO"
let bleYes                  = "YES"
let bleDone                 = "DONE"

enum State: Int {
    case Zero           = 0
    case One            = 1
    case Two            = 2
    case Three          = 3
    case Four           = 4
    case Five           = 5
    case Six            = 6
    case Seven          = 7
    case Eight          = 8
    case Nine           = 9
    case Ten            = 10
    case Eleven         = 11
};

private let simpleStringMaxLength               = 17
private let extrasStringMaxLength               = 14

private let connectMeterTime: NSTimeInterval    = 5     // seconds

private let numberOfStableReceivedMessages      = 20

private let characteristicValue         = "00000211-4E86-33A6-7756-0085AE176122"
private let characteristicText          = "00000212-4E86-33A6-7756-0085AE176122"
private let characteristicConfirmation  = "00000213-4E86-33A6-7756-0085AE176122"
private let characteristicToken         = "00000214-4E86-33A6-7756-0085AE176122"

private struct Peripheral {
    let device: CBPeripheral
    let rssi: Int
    var enableDelegates: Bool
    var numberOfMessages: Int {
        willSet {
            // Enable some delegates when currently active peripheral is stable enough
            enableDelegates = newValue > numberOfStableReceivedMessages
        }
    }
    
    init(device: CBPeripheral, rssi: Int) {
        self.device = device
        self.rssi = rssi
        self.enableDelegates = false
        self.numberOfMessages = 0
    }
}

class BLEController: NSObject, CBCentralManagerDelegate, CBPeripheralDelegate {
    
    static let sharedInstance = BLEController()
    
    private var centralManager: CBCentralManager!
    private var activePeripheral: Peripheral?
    private weak var advTimer, connectTimer: NSTimer?
    private var isScanning = false
    private var confirmationCharacteristic, tokenCharacteristic: CBCharacteristic?
    private var extrasDictionary = [String: String]()
    private var latestBroadcastingDictionary = [String: AnyObject]()
    private var characteristicsSet = Set<String>()
    
    var delegate: BLEControllerDelegate?
    
    private override init() {
        super.init()
        
        let bleOptions = [CBCentralManagerOptionShowPowerAlertKey: true,
                          CBCentralManagerScanOptionAllowDuplicatesKey: true]
        
        // Power on bluetooth module
        self.centralManager = CBCentralManager(delegate: self, queue: nil, options: bleOptions)
    }
    
    // MARK: - CBCentralManager delegates
    
    func centralManagerDidUpdateState(central: CBCentralManager) {
        switch central.state {
        case .Unknown:
            print("Unknown")
            
        case .Resetting:
            print("Resetting")
            
        case .Unsupported:
            print("Unsupported")
            
        case .Unauthorized:
            print("Unauthorized")
            
        case .PoweredOff:
            print("Powered off")
            self.delegate?.didBLEPowerOff?()
            
        case .PoweredOn:
            print("Powered on")
            self.delegate?.didBLEPowerOn?()
        }
    }
    
    func centralManager(central: CBCentralManager, didDiscoverPeripheral peripheral: CBPeripheral, advertisementData: [String : AnyObject], RSSI: NSNumber) {
        
        // Get service data from a broadcast request
        if let serviceDic = advertisementData[CBAdvertisementDataServiceDataKey] as? NSDictionary {
            
            let serviceData = serviceDic.description
            
            let equalSignLocation = serviceData.rangeOfString("\\")?.startIndex
            
            // Make sure it is our messge
            if (RSSI.intValue > 0 ||
                serviceData.characters.count < 69 ||
                nil == equalSignLocation ||
                nil == serviceData.rangeOfString("0770")) {
                return
            }
            
            if let active = activePeripheral {
                if active.device.identifier.UUIDString != peripheral.identifier.UUIDString {
                    // New peripheral (with different UUID)
                    if active.rssi > RSSI.integerValue {
                        // Weaker signal, ignore it
                        return
                    }
                    else {
                        // Stronger signal, update peripheral
                        activePeripheral = nil
                        activePeripheral = Peripheral(device: peripheral,
                                                      rssi: RSSI.integerValue)
                    }
                }
                else if !activePeripheral!.enableDelegates {
                    // Update statistics of the currently active peripheral
                    activePeripheral!.numberOfMessages += 1
                }
            }
            else {
                // Store first peripheral
                activePeripheral = Peripheral(device: peripheral,
                                              rssi: RSSI.integerValue)
            }
            
            // Index of the data to be processed (in 11 bytes after "\")
            let broadcastDataIndex = equalSignLocation!.advancedBy(11)
            
            // Data to be processed
            let broadcastData = serviceData.substringFromIndex(broadcastDataIndex)
            
            // Form a real array of binary data to be processed
            var advBinArray = formAdvBinArray(broadcastData)
            
            // Decrypt first 24 bytes
            // 25th byte is not encrypted - do not change it
            decryptBinArray(&advBinArray, withLength: 24)
            
            if activePeripheral!.enableDelegates {
                // Parse decrypted broadcast message
                parseData(advBinArray, forDevice: peripheral.identifier.UUIDString)
            }
            
            restartAdvTimer()
        }
    }
    
    func centralManager(central: CBCentralManager, didFailToConnectPeripheral peripheral: CBPeripheral, error: NSError?) {
        self.delegate?.didBLEFailConnect?()
    }
    
    func centralManager(central: CBCentralManager, didConnectPeripheral peripheral: CBPeripheral) {
        // Remove all previously discovered characteristics
        characteristicsSet.removeAll()
        activePeripheral?.device.delegate = self
        activePeripheral?.device.discoverServices(nil)
    }
    
    func centralManager(central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: NSError?) {
        
        if nil != error {
            print("\(error!.localizedDescription) at disconnect peripheral")
            return
        }
        
        self.delegate?.didBLEDisconnect?()
    }
    
    func peripheral(peripheral: CBPeripheral, didDiscoverServices error: NSError?) {
        
        if nil != error {
            print("\(error!.localizedDescription) at discovery services")
            return
        }
        
        for service in peripheral.services! {
            peripheral.discoverCharacteristics(nil, forService: service)
        }
    }
    
    func peripheral(peripheral: CBPeripheral, didDiscoverCharacteristicsForService service: CBService, error: NSError?) {
        
        if nil != error {
            print("\(error!) at discover characteristics for service \(service)")
        }
        
        for characteristic in service.characteristics! {
            
            switch characteristic.UUID.description {
            case characteristicValue, characteristicText:
                peripheral.setNotifyValue(true, forCharacteristic: characteristic)
                addCharacteristic(characteristic.UUID.description)
                
            case characteristicConfirmation:
                confirmationCharacteristic = characteristic
                addCharacteristic(characteristic.UUID.description)
                
            case characteristicToken:
                tokenCharacteristic = characteristic
                addCharacteristic(characteristic.UUID.description)
                
            default:
                break
            }
        }
    }
    
    func peripheral(peripheral: CBPeripheral, didUpdateValueForCharacteristic characteristic: CBCharacteristic, error: NSError?) {
        
        if nil != error {
            print("\(error?.localizedDescription) at updating of value")
            return
        }
        
        switch characteristic.UUID.description {
        case characteristicValue:
            var v3 = 0
            // Read value from the characteristic
            characteristic.value?.getBytes(&v3, length: sizeof(Int))
            if v3 > 0 {
                self.delegate?.didBLEUpdateValue3?(v3)
            }
            
        case characteristicText:
            // Read text from the characteristic
            if let text = String(data: characteristic.value!,
                                 encoding: NSUTF8StringEncoding) {
                if !text.isEmpty {
                    self.delegate?.didBLEUpdateText2?(text)
                }
            }
            
        case characteristicToken, characteristicConfirmation:
            // Read the value from the characteristic
            if let text = String(data: characteristic.value!,
                                 encoding: NSUTF8StringEncoding) {
                // Send confirmation with previously written value
                self.delegate?.didBLESendConfirmation?(text)
            }
            
        default:
            break
        }
    }
    
    func peripheral(peripheral: CBPeripheral, didUpdateNotificationStateForCharacteristic characteristic: CBCharacteristic, error: NSError?) {
        
        if nil != error {
            print("\(error!.localizedDescription) at update notification state for \(characteristic.UUID)")
            return
        }
        
        if characteristic.isNotifying {
            peripheral.readValueForCharacteristic(characteristic)
        }
    }
    
    func peripheral(peripheral: CBPeripheral, didWriteValueForCharacteristic characteristic: CBCharacteristic, error: NSError?) {
        if nil != error {
            print("\(error!.localizedDescription) at writing characteristic \(characteristic.UUID)")
            return
        }
        // The value was successfully written, read it to return written value
        peripheral.readValueForCharacteristic(characteristic)
    }
    
    // MARK: - Public methods
    
    func startScan() {
        let scanOptions = [CBCentralManagerScanOptionAllowDuplicatesKey: true]
        centralManager.scanForPeripheralsWithServices(nil, options: scanOptions)
        isScanning = true
    }
    
    func stopScan() {
        centralManager.stopScan()
        stopAdvTimer()
        isScanning = false
    }
    
    func isConnected() -> Bool {
        guard let state = activePeripheral?.device.state else {
            return false
        }
        
        return CBPeripheralState.Connected == state
    }
    
    func connect() {
        stopAdvTimer()
        stopConnectTimer()
        connectTimer = NSTimer.scheduledTimerWithTimeInterval(connectMeterTime,
                                                              target: self,
                                                              selector: #selector(connectMeterTimeout),
                                                              userInfo: nil,
                                                              repeats: false)
        centralManager.connectPeripheral(activePeripheral!.device, options: nil)
    }
    
    func disconnect() {
        if (nil != activePeripheral) &&
            (CBPeripheralState.Connected == activePeripheral?.device.state) {
            centralManager.cancelPeripheralConnection(activePeripheral!.device)
            stopScan()
            latestBroadcastingDictionary.removeAll()
            activePeripheral = nil
        }
    }
    
    func sendToken(data: String) {
        guard let characteristic = tokenCharacteristic else {
            return
        }
        
        guard let value = data.dataUsingEncoding(NSUTF8StringEncoding) else {
            return
        }
        
        activePeripheral?.device.writeValue(value,
                                            forCharacteristic: characteristic,
                                            type: CBCharacteristicWriteType.WithResponse)
    }
    
    func sendConfirmation(data: String) {
        guard let characteristic = confirmationCharacteristic else {
            return
        }
        
        guard let value = data.dataUsingEncoding(NSUTF8StringEncoding) else {
            return
        }
        
        activePeripheral?.device.writeValue(value,
                                            forCharacteristic: characteristic,
                                            type: CBCharacteristicWriteType.WithResponse)
    }
    
    func latestBroadcastingData() {
        
        // Send any available information received from broadcast messages
        
        if let v1 = latestBroadcastingDictionary[latestValue1] as? Int {
            self.delegate?.didBLEUpdateValue1?(v1)
        }
        
        if let iconName = latestBroadcastingDictionary[latestIcon] as? String {
            self.delegate?.didBLEUpdateIcon?(iconName)
        }
        
        if let v2 = latestBroadcastingDictionary[latestValue2] as? Int {
            self.delegate?.didBLEUpdateValue2?(v2)
        }
        
        if let text = latestBroadcastingDictionary[latestID1] as? String {
            self.delegate?.didBLEUpdateText1?(text)
        }
        
        if let list = latestBroadcastingDictionary[latestList] as? [String: String] {
            self.delegate?.didBLEUpdateList?(list)
        }
    }
    
    // MARK: - Private methods
    
    // Parse advertisement data
    private func parseData(data: [UInt8], forDevice: String) {
        // Check IPP state
        if let state = State(rawValue: Int(data[0] >> 4)) {
            switch state {
            case .Zero, .One, .Six:
                // Ignore IPP with such states
                activePeripheral = nil
                self.delegate?.didBLEUpdateState?(state.rawValue)
                
            default:
                if activePeripheral!.enableDelegates {
                    self.delegate?.didBLEUpdateState?(state.rawValue)
                    latestBroadcastingDictionary[latestState] = state.rawValue
                }
            }
        }
        
        // Array of possible icon names
        let iconNames = ["icon1.png",
                         "icon2.png",
                         "icon3.png",
                         "icon4.png",
                         "icon5.png",
                         "icon6.png",
                         "icon7.png"];
        
        // Get icon index
        let iconIndex = Int(data[0] & 0x07);
        if iconIndex < iconNames.count {
            self.delegate?.didBLEUpdateIcon?(iconNames[iconIndex])
            latestBroadcastingDictionary[latestIcon] = iconNames[iconIndex]
        }
        
        // First value
        let v1 = (Int(data[1]) << 16) + (Int(data[2]) << 8) + Int(data[3])
        if 0 != v1 {
            self.delegate?.didBLEUpdateValue1?(v1)
            latestBroadcastingDictionary[latestValue1] = v1
        }
        
        // Second value
        let v2 = (Int(data[4]) << 8) + Int(data[5])
        self.delegate?.didBLEUpdateValue2?(v2)
        latestBroadcastingDictionary[latestValue2] = v2
        
        // Data type
        let dataType = data[6]
        switch dataType {
        case 0x00:
            let text = stringFromArray(data[7..<7 + simpleStringMaxLength])
            self.delegate?.didBLEUpdateText1?(text)
            latestBroadcastingDictionary[latestText] = text
            
        case 0x01:
            let text = stringFromArray(data[7..<13]) + " "
                + stringFromArray(data[13..<19]) + " "
                + stringFromArray(data[19..<25])
            
            self.delegate?.didBLEUpdateText1?(text)
            latestBroadcastingDictionary[latestText] = text
            
        case 0x20:
            let text = stringFromArray(data[7..<7 + simpleStringMaxLength])
            self.delegate?.didBLEUpdateID1?(text)
            latestBroadcastingDictionary[latestID1] = text
            
        case 0x21:
            let text = stringFromArray(data[7..<7 + simpleStringMaxLength])
            self.delegate?.didBLEUpdateID2?(text)
            latestBroadcastingDictionary[latestID2] = text
            
        default:
            break
        }
        
        // Extras
        if dataType >= 0x80 && dataType < 0xC0 {
            let extraAmount = (Int(data[7]) << 8) + Int(data[8])
            
            var extraText = stringFromArray(data[9..<9 + extrasStringMaxLength])
            
            if !extraText.isEmpty {
                if (dataType >= 0x80 && dataType < 0xA0) || 0xBE == dataType {
                    extraText += " PPP"
                }
                else if 0xBF != dataType {
                    extraText += " MAIL"
                }
                
                if 0 == extraAmount {
                    // Delete a pair with zero amount from the dictionary
                    extrasDictionary[extraText] = nil
                }
                else {
                    let extraAmountText = String(format: "%d.%02d",
                                                 extraAmount / 100,  extraAmount % 100)
                    
                    // Add new extraText:extraAmountText pair to the dictionary
                    extrasDictionary[extraText] = extraAmountText
                }
            }
            
            self.delegate?.didBLEUpdateList?(extrasDictionary)
            latestBroadcastingDictionary[latestList] = extrasDictionary
        }
    }
    
    // Add discovered characteristic
    private func addCharacteristic(c: String) {
        
        // Array of characteristics that must be discovered
        let allCharacteristics = [characteristicValue,
                                  characteristicText,
                                  characteristicConfirmation,
                                  characteristicToken]
        
        characteristicsSet.insert(c)
        
        if characteristicsSet.count == allCharacteristics.count {
            // All necessary characteristics have been discovered
            stopConnectTimer()
            stopScan()
            latestBroadcastingDictionary.removeAll()
            self.delegate?.didBLEConnect?()
        }
    }
    
    // Stop connect timer
    private func stopConnectTimer() {
        connectTimer?.invalidate()
        connectTimer = nil
    }
    
    @objc private func connectMeterTimeout() {
        stopConnectTimer()
        latestBroadcastingDictionary.removeAll()
        self.delegate?.didBLEFailConnect?()
    }
    
    // Stop advertisement timer
    private func stopAdvTimer() {
        advTimer?.invalidate()
        advTimer = nil
    }
    
    // Restart advertisement timer
    private func restartAdvTimer() {
        stopAdvTimer()
        
        if nil != centralManager && isScanning {
            
            // Run advertisement timer for 2 seconds
            advTimer = NSTimer.scheduledTimerWithTimeInterval(2,
                                                              target: self,
                                                              selector: #selector(timeoutAdvTimer),
                                                              userInfo: nil,
                                                              repeats: false)
        }
    }
    
    @objc private func timeoutAdvTimer() {
        stopAdvTimer()
        activePeripheral = nil
        
        if isScanning {
            startScan()
        }
        
        self.delegate?.didBLELoseBroadcast?()
    }
    
    private func stringFromArray(array: ArraySlice<UInt8>) -> String {
        
        guard var string = String(bytes: array, encoding: NSUTF8StringEncoding) else {
            return ""
        }
        
        // Remove all spaces at the end of extra text
        string = string.stringByTrimmingCharactersInSet(NSCharacterSet.whitespaceCharacterSet())
        // Remove all zero characters
        string = string.stringByReplacingOccurrencesOfString("\0", withString: "")
        return string
    }
    
    // Form an array of data received from BLE driver without service characters
    private func formAdvArray(data: String) -> [UInt8] {
        
        var array = [UInt8]()
        var dataIndex = data.startIndex
        
        while array.count < 50 {
            let c = data[dataIndex]
            
            if " " != c {
                // Store ASCII codes of advertisement data
                let s = String(c).unicodeScalars
                array.append(UInt8(s[s.startIndex].value))
            }
            dataIndex = dataIndex.successor()
        }
        
        return array
    }
    
    // Form an array of binary data received from BLE driver
    private func formAdvBinArray(data: String) -> [UInt8] {
        
        // Array of ASCII characters
        var advArray = formAdvArray(data)
        var advBinArray = [UInt8]()
        
        // Convert ASCII bytes into hex
        var i = 0
        while i < advArray.count {
            // Store hex codes of advertisement data
            advBinArray.append(ascToHex(advArray[i], lo: advArray[i + 1]))
            i += 2
        }
        
        return advBinArray
    }
    
    // Decrypt binary array
    private func decryptBinArray(inout data: [UInt8], withLength: Int) {
        // Convert binary bytes into NSData
        let encryptedData = NSData(bytes: data as [UInt8], length: withLength)
        
        // Decrypt data
        let decryptedData = Cryptor.sharedStore().cryptData(encryptedData,
                                                            withOperation: false)
        
        // Store decrypted bytes back in array
        decryptedData.getBytes(&data, length: withLength)
    }
    
    // Convert ASCII digits into to hex
    private func ascHex(asciiCode: UInt8) -> UInt8 {
        let hex = asciiCode - 0x30
        return hex > 9 ? hex - 7 : hex
    }
    
    // Convert 2 ASCII digits into one hex byte
    private func ascToHex(hi: UInt8, lo: UInt8) -> UInt8 {
        return (ascHex(hi) << 4) | (ascHex(lo) & 0x0F)
    }
}
