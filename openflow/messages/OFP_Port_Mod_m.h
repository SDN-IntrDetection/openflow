//
// Generated file, do not edit! Created by nedtool 4.6 from messages/OFP_Port_Mod.msg.
//

#ifndef _OFP_PORT_MOD_M_H_
#define _OFP_PORT_MOD_M_H_

#include <omnetpp.h>

// nedtool version check
#define MSGC_VERSION 0x0406
#if (MSGC_VERSION!=OMNETPP_VERSION)
#    error Version mismatch! Probably this file was generated by an earlier version of nedtool: 'make clean' should help.
#endif



// cplusplus {{
    #include "openflow.h"
    #include "Open_Flow_Message_m.h"    
    
// }}

/**
 * Class generated from <tt>messages/OFP_Port_Mod.msg:13</tt> by nedtool.
 * <pre>
 * packet OFP_Port_Mod extends Open_Flow_Message
 * {
 *     uint32_t port_no;
 *     //uint8_t pad[4];
 *     uint8_t hw_addr[6];
 *     //uint8_t pad2[2];        //Pad to 64 bits.
 *     uint32_t config;          //Bitmap of OFPPC_* flags.
 *     uint32_t mask;            //Bitmap of OFPPC_* flags to be changed.
 *     uint32_t advertise;       //Bitmap of OFPPF_*.  Zero all bits to prevent any action taking place.
 * 	//uint8_t pad3[4];        //Pad to 64 bits
 * }
 * </pre>
 */
class OFP_Port_Mod : public ::Open_Flow_Message
{
  protected:
    uint32_t port_no_var;
    uint8_t hw_addr_var[6];
    uint32_t config_var;
    uint32_t mask_var;
    uint32_t advertise_var;

  private:
    void copy(const OFP_Port_Mod& other);

  protected:
    // protected and unimplemented operator==(), to prevent accidental usage
    bool operator==(const OFP_Port_Mod&);

  public:
    OFP_Port_Mod(const char *name=NULL, int kind=0);
    OFP_Port_Mod(const OFP_Port_Mod& other);
    virtual ~OFP_Port_Mod();
    OFP_Port_Mod& operator=(const OFP_Port_Mod& other);
    virtual OFP_Port_Mod *dup() const {return new OFP_Port_Mod(*this);}
    virtual void parsimPack(cCommBuffer *b);
    virtual void parsimUnpack(cCommBuffer *b);

    // field getter/setter methods
    virtual uint32_t getPort_no() const;
    virtual void setPort_no(uint32_t port_no);
    virtual unsigned int getHw_addrArraySize() const;
    virtual uint8_t getHw_addr(unsigned int k) const;
    virtual void setHw_addr(unsigned int k, uint8_t hw_addr);
    virtual uint32_t getConfig() const;
    virtual void setConfig(uint32_t config);
    virtual uint32_t getMask() const;
    virtual void setMask(uint32_t mask);
    virtual uint32_t getAdvertise() const;
    virtual void setAdvertise(uint32_t advertise);
};

inline void doPacking(cCommBuffer *b, OFP_Port_Mod& obj) {obj.parsimPack(b);}
inline void doUnpacking(cCommBuffer *b, OFP_Port_Mod& obj) {obj.parsimUnpack(b);}


#endif // ifndef _OFP_PORT_MOD_M_H_

