Jump tables
===========

Copy link[](https://twitter.com/intent/tweet?text=https://hex-rays.com/blog/jump-tables)[](https://mastodon.social/share?text=%20https://hex-rays.com/blog/jump-tables)[](https://www.linkedin.com/shareArticle?mini=true&url=https://hex-rays.com/blog/jump-tables)

  Ilfak Guilfanov ✦ Posted: Jan 31, 2008

![Jump tables](https://hex-rays.com/hubfs/Imported_Blog_Media/bg-banner-Jun-18-2024-09-07-48-3471-AM.png)

It is an endless story: regardless of how many different jump table types IDA supports, there will be a new unhandled twist. Be it the instruction scheduler, which rearranged the instructions in an unexpected manner, or the compiler, which learned a new optimization trick, it is the same for IDA: jump tables are missed and functions boundaries are wrong. What’s worse, the graph view, so loved by IDA users, displays a trimmed graph without jump tables, virtually useless for any analysis.

That’s why we strive to add support for new jump tables to IDA, and since it can not be done for all of them, we focus on compiler generated jump tables for popular processors. Take ARM, for example. The ARM processor module have been improved a lot in v5.2, but yet we received a report with a bunch of new patterns. So expect even better support for ARM in the near future 🙂

If you are interested in improving the jump table handling for a rarely used processor, here are the explanations how to do it.  

First, you’ll need to hook to the emulation step of the analysis.This way your plugin will be called by the kernel as soon as the instructions that handles the jump table are analyzed. You can do it in many ways, I present 2 of them here:

*   hook to processor events and intercept the **custom\_emu** event.
    
    hook\_to\_notification\_point(HT\_IDP, my\_handler, NULL);  
    …  
    static int my\_handler(void \*, int code, va\_list va)  
    {  
    if ( code == processor\_t::custom\_emu )  
    {  
    // check the instruction (see ‘cmd’ structure)  
    // and create switch\_info\_ex\_t  
    }  
    }
    
*   you may also replace **ph.is\_switch()** pointer by your function. This callback is used  
    only for indirect jump instructions, so your handler will be called only for them.

The task of recognizing an instruction sequence has not been formalized yet,  
so you are basically at your own here. Check the processor module samples in the SDK,  
or implement your own pattern matcher. In the SDK there is a file named  
_jptcmn.cpp_, it contains an instruction sequence matcher used by a  
few IDA modules. But I have to admit that it is quite difficult to use and does  
not handle everything. However, it still can overcome some instruction shuffling and  
register substitutions. Please check the samples in the SDK to see how it is used.

After recognizing a jump table, the IDA kernel should be informed about it.  
The structure that holds the jump table information is called **switch\_info\_ex\_t**.  
The following details are stored:

*   **jumps**: The address of the jump table
*   Element size for the jump table
*   **ncases**: Number of elements
*   **defjump**: The address where the execution continues if the control variable is out of range (**default** jump address)
*   **startea**: The address of the beginning of the switch idiom

and lots of flags and additional information about the table, like if the table  
elements are signed or unsigned, if a separate value table is present, if the jump  
table has a custom structure, etc. The **switch\_info\_ex\_t** structure  
is quite complex but it can be used to describe virtually any jump table.

In the simplest case, a plain 32-bit jump table with elements that contain  
target addresses, the structure is filled like this:

switch\_info\_ex\_t si;  
si.set\_jtable\_element\_size(4);// 32-bit jump offsets  
si.ncases = n; // we specify the table size  
si.jumps = jump\_table\_ea; // the table address  
si.startea = cmd.ea; // address of the first instruction  
// related to the jump table

If we have more information about the jump table, we can add it to the structure.  
If we know the **default** jump address:

si.flags |= SWI\_DEFAULT;  
si.defjump = default\_jump\_ea;

If we know the input register used by the table jump:

si.set\_expr(regnum, reg\_dttyp);

If a delta is subtracted from the input value before using it:

si.lowcase = delta;

If the table entries are shifted to the left before used:

si.set\_shift(shift\_amount);

If there is a separate value table:

si.flags |= SWI\_SPARSE;  
si.set\_vtable\_element\_size(value\_size);

If the value table are used as indexes into the jump table:

si.flags2 |= SWI2\_INDIRECT;

Finally, if the jump table has a special structure, then you can set:

si.flags |= SWI\_CUSTOM;  
si.custom = value\_of\_your\_choice;

Naturally, the more information you put into **switch\_info\_ex\_t**, the better  
the analysis will be. The prepared structure must be stored into the database:

set\_switch\_info\_ex(ea, &si);  
setFlbits(ea, FF\_JUMP);

For regular jump tables, the kernel will handle the rest. For custom tables,  
the kernel will generate the **create\_switch\_xrefs** and  
**calc\_switch\_cases** events. Your module must intercept them  
and either create cross references or calculate the requested information.

One more trick: you may also intercept the **processor\_t::is\_insn\_table\_jump** event  
to prevent the kernel from creating jump tables when it should not. The kernel  
has some heuristic rules to create jump tables. If they create wrong jump tables,  
you can intercept their creation at this event.

This was a very short introduction to the jump tables in IDA Pro. Feel free to post your questions in the forum, I’ll be glad to answer!
