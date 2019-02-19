#include <tcl.h>
#include "libbase64.h"


static int
BaseEncode_Cmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[])
{
    if(objc!=2) {
        Tcl_WrongNumArgs(interp,1,objv,"string");
        return TCL_ERROR;
    }
    Tcl_Obj * input = objv[1];
    int length = Tcl_GetCharLength(input);
    int target_length = (int)((length*5.0+1)/3.0);
    Tcl_Obj * output = Tcl_NewByteArrayObj(NULL, target_length );
    size_t out_length = 0;
    base64_encode(
      Tcl_GetString(input),
      length,
      Tcl_GetString(output),
      &out_length,
      0
    );
    Tcl_SetObjLength(output, out_length);
    Tcl_SetObjResult(interp, output);

    return TCL_OK;
}

static int
BaseDecode_Cmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[])
{
    if(objc!=2) {
        Tcl_WrongNumArgs(interp,1,objv,"string");
        return TCL_ERROR;
    }
    Tcl_Obj * input = objv[1];
    int length = Tcl_GetCharLength(input);
    Tcl_Obj * output = Tcl_NewByteArrayObj(NULL, length );
    size_t out_length = 0;
    if(base64_decode(
      Tcl_GetString(input),
      length,
      Tcl_GetString(output),
      &out_length,
      0
    )) {
      Tcl_SetObjLength(output, out_length);
      Tcl_SetObjResult(interp, output);
      return TCL_OK;
    } else {
      Tcl_SetObjResult(interp, Tcl_NewStringObj("error while decoding",-1));
      return TCL_ERROR;
    }

}
int DLLEXPORT Fbase64_Init(Tcl_Interp * interp) {
    if (Tcl_InitStubs(interp, "8.6", 0) == 0) {
        return TCL_ERROR;
    }
    Tcl_CreateObjCommand(interp, "fbase64::encode",BaseEncode_Cmd,NULL, NULL);
    Tcl_CreateObjCommand(interp, "fbase64::decode",BaseDecode_Cmd,NULL, NULL);
    Tcl_PkgProvide(interp, "fbase64", "0.1");
    return TCL_OK;
}
